package luascript

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const (
	maxJSONBytes = 256 * 1024
	maxJSONDepth = 32
	maxKVKeys    = 1000
	maxKVKeyLen  = 128
	maxKVValue   = 16 * 1024
	maxKVTotal   = 1 << 20
)

// KV is the persistent per script key/value store. It lives in memory (cleared on restart), is shared by every
// run of the script and bounded in number of keys and bytes.
type KV struct {
	mu    sync.Mutex
	items map[string]kvItem
	size  int
}

type kvItem struct {
	v   lua.LValue // string, number or bool
	exp time.Time
	n   int
}

func NewKV() *KV { return &KV{items: map[string]kvItem{}} }

func (k *KV) get(key string, now time.Time) lua.LValue {
	k.mu.Lock()
	defer k.mu.Unlock()
	it, ok := k.items[key]
	if !ok {
		return lua.LNil
	}
	if !it.exp.IsZero() && now.After(it.exp) {
		k.size -= it.n
		delete(k.items, key)
		return lua.LNil
	}
	return it.v
}

func (k *KV) set(key string, v lua.LValue, ttl time.Duration, now time.Time) error {
	if len(key) == 0 || len(key) > maxKVKeyLen {
		return fmt.Errorf("kv key must be 1-%d bytes", maxKVKeyLen)
	}
	n := len(key)
	switch t := v.(type) {
	case lua.LString:
		if len(t) > maxKVValue {
			return fmt.Errorf("kv value larger than %d bytes", maxKVValue)
		}
		n += len(t)
	case lua.LNumber, lua.LBool:
		n += 8
	default:
		return fmt.Errorf("kv values must be strings, numbers or booleans")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	old, had := k.items[key]
	if had {
		k.size -= old.n
		delete(k.items, key)
	}
	if len(k.items) >= maxKVKeys {
		//Drop expired entries first
		for kk, it := range k.items {
			if !it.exp.IsZero() && now.After(it.exp) {
				k.size -= it.n
				delete(k.items, kk)
			}
		}
		if len(k.items) >= maxKVKeys {
			return fmt.Errorf("kv store is full (%d keys)", maxKVKeys)
		}
	}
	if k.size+n > maxKVTotal {
		return fmt.Errorf("kv store is full (%d bytes)", maxKVTotal)
	}
	it := kvItem{v: v, n: n}
	if ttl > 0 {
		it.exp = now.Add(ttl)
	}
	k.items[key] = it
	k.size += n
	return nil
}

func (k *KV) del(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if it, ok := k.items[key]; ok {
		k.size -= it.n
		delete(k.items, key)
	}
}

// Len returns the number of stored keys (tests, status)
func (k *KV) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.items)
}

var (
	kvStoresMu sync.Mutex
	kvStores   = map[string]*KV{}
)

// StoreFor returns the persistent KV store of a named script (kept across edits of the script, bounded count)
func StoreFor(name string) *KV {
	kvStoresMu.Lock()
	defer kvStoresMu.Unlock()
	if s, ok := kvStores[name]; ok {
		return s
	}
	if len(kvStores) >= 1000 {
		return NewKV() //too many scripts: this one does not persist
	}
	s := NewKV()
	kvStores[name] = s
	return s
}

func installLibs(L *lua.LState, r *runState) {
	// json
	j := L.NewTable()
	L.SetField(j, "encode", L.NewFunction(func(L *lua.LState) int {
		v, err := toGo(L.CheckAny(1), 0)
		if err != nil {
			L.RaiseError("json.encode: %s", err.Error())
		}
		b, err := json.Marshal(v)
		if err != nil {
			L.RaiseError("json.encode: %s", err.Error())
		}
		if len(b) > maxJSONBytes {
			L.RaiseError("json.encode: result too large")
		}
		L.Push(lua.LString(b))
		return 1
	}))
	L.SetField(j, "decode", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(1)
		if len(s) > maxJSONBytes {
			L.RaiseError("json.decode: input too large")
		}
		var v interface{}
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid json: " + cleanErr(err.Error())))
			return 2
		}
		lv, err := fromGo(L, v, 0)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(lv)
		return 1
	}))
	L.SetGlobal("json", j)

	// base64 / hex / url
	b64 := L.NewTable()
	L.SetField(b64, "encode", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(base64.StdEncoding.EncodeToString([]byte(L.CheckString(1)))))
		return 1
	}))
	L.SetField(b64, "decode", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(1)
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			if b, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString("invalid base64"))
				return 2
			}
		}
		L.Push(lua.LString(b))
		return 1
	}))
	L.SetField(b64, "urlencode", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(base64.RawURLEncoding.EncodeToString([]byte(L.CheckString(1)))))
		return 1
	}))
	L.SetGlobal("base64", b64)

	hx := L.NewTable()
	L.SetField(hx, "encode", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(hex.EncodeToString([]byte(L.CheckString(1)))))
		return 1
	}))
	L.SetField(hx, "decode", L.NewFunction(func(L *lua.LState) int {
		b, err := hex.DecodeString(L.CheckString(1))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid hex"))
			return 2
		}
		L.Push(lua.LString(b))
		return 1
	}))
	L.SetGlobal("hex", hx)

	u := L.NewTable()
	L.SetField(u, "escape", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(url.QueryEscape(L.CheckString(1))))
		return 1
	}))
	L.SetField(u, "unescape", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(queryUnescape(L.CheckString(1))))
		return 1
	}))
	L.SetGlobal("url", u)

	// crypto
	c := L.NewTable()
	L.SetField(c, "sha256", L.NewFunction(func(L *lua.LState) int {
		sum := sha256.Sum256([]byte(L.CheckString(1)))
		L.Push(lua.LString(hex.EncodeToString(sum[:])))
		return 1
	}))
	L.SetField(c, "hmac_sha256", L.NewFunction(func(L *lua.LState) int {
		m := hmac.New(sha256.New, []byte(L.CheckString(1)))
		m.Write([]byte(L.CheckString(2)))
		L.Push(lua.LString(hex.EncodeToString(m.Sum(nil))))
		return 1
	}))
	L.SetField(c, "equals", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LBool(subtle.ConstantTimeCompare([]byte(L.CheckString(1)), []byte(L.CheckString(2))) == 1))
		return 1
	}))
	L.SetGlobal("crypto", c)

	// time
	t := L.NewTable()
	L.SetField(t, "now", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(float64(time.Now().UnixNano()) / 1e9))
		return 1
	}))
	L.SetField(t, "format", L.NewFunction(func(L *lua.LState) int {
		ts := float64(L.CheckNumber(1))
		layout := L.OptString(2, time.RFC3339)
		if len(layout) > 64 || math.IsNaN(ts) || math.IsInf(ts, 0) || math.Abs(ts) > 1e11 {
			L.ArgError(1, "invalid time or layout")
		}
		sec := math.Floor(ts)
		L.Push(lua.LString(time.Unix(int64(sec), int64((ts-sec)*1e9)).UTC().Format(layout)))
		return 1
	}))
	L.SetGlobal("time", t)

	// kv
	k := L.NewTable()
	L.SetField(k, "get", L.NewFunction(func(L *lua.LState) int {
		L.Push(r.kv.get(L.CheckString(1), time.Now()))
		return 1
	}))
	L.SetField(k, "set", L.NewFunction(func(L *lua.LState) int {
		ttl := time.Duration(float64(L.OptNumber(3, 0)) * float64(time.Second))
		if err := r.kv.set(L.CheckString(1), L.CheckAny(2), ttl, time.Now()); err != nil {
			L.RaiseError("kv.set: %s", err.Error())
		}
		return 0
	}))
	L.SetField(k, "delete", L.NewFunction(func(L *lua.LState) int {
		r.kv.del(L.CheckString(1))
		return 0
	}))
	L.SetField(k, "incr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		by := float64(L.OptNumber(2, 1))
		ttl := time.Duration(float64(L.OptNumber(3, 0)) * float64(time.Second))
		//Not atomic across the get/set pair; good enough for counters in a pool of at most 32 runs
		r.kv.mu.Lock()
		it, ok := r.kv.items[key]
		r.kv.mu.Unlock()
		cur := 0.0
		if ok && (it.exp.IsZero() || time.Now().Before(it.exp)) {
			if n, isNum := it.v.(lua.LNumber); isNum {
				cur = float64(n)
			}
		}
		cur += by
		if err := r.kv.set(key, lua.LNumber(cur), ttl, time.Now()); err != nil {
			L.RaiseError("kv.incr: %s", err.Error())
		}
		L.Push(lua.LNumber(cur))
		return 1
	}))
	L.SetGlobal("kv", k)
}

// toGo converts a Lua value to a JSON-able Go value (cycles and depth are rejected)
func toGo(v lua.LValue, depth int) (interface{}, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("nesting deeper than %d (cycle?)", maxJSONDepth)
	}
	switch t := v.(type) {
	case *lua.LNilType:
		return nil, nil
	case lua.LBool:
		return bool(t), nil
	case lua.LNumber:
		f := float64(t)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("cannot encode NaN or Inf")
		}
		if f == math.Trunc(f) && math.Abs(f) < 1e15 {
			return int64(f), nil
		}
		return f, nil
	case lua.LString:
		return string(t), nil
	case *lua.LTable:
		if t.MaxN() > 0 && t.Len() == t.MaxN() {
			arr := make([]interface{}, 0, t.MaxN())
			for i := 1; i <= t.MaxN(); i++ {
				e, err := toGo(t.RawGetInt(i), depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, e)
			}
			return arr, nil
		}
		m := map[string]interface{}{}
		var ferr error
		t.ForEach(func(k, val lua.LValue) {
			if ferr != nil {
				return
			}
			var ks string
			switch kt := k.(type) {
			case lua.LString:
				ks = string(kt)
			case lua.LNumber:
				ks = kt.String()
			default:
				ferr = fmt.Errorf("table keys must be strings or numbers")
				return
			}
			e, err := toGo(val, depth+1)
			if err != nil {
				ferr = err
				return
			}
			m[ks] = e
		})
		if ferr != nil {
			return nil, ferr
		}
		return m, nil
	}
	return nil, fmt.Errorf("cannot encode a %s", v.Type().String())
}

func fromGo(L *lua.LState, v interface{}, depth int) (lua.LValue, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("json nested deeper than %d", maxJSONDepth)
	}
	switch t := v.(type) {
	case nil:
		return lua.LNil, nil
	case bool:
		return lua.LBool(t), nil
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return nil, err
		}
		return lua.LNumber(f), nil
	case string:
		return lua.LString(t), nil
	case []interface{}:
		tb := L.NewTable()
		for _, e := range t {
			lv, err := fromGo(L, e, depth+1)
			if err != nil {
				return nil, err
			}
			tb.Append(lv)
		}
		return tb, nil
	case map[string]interface{}:
		tb := L.NewTable()
		for k, e := range t {
			lv, err := fromGo(L, e, depth+1)
			if err != nil {
				return nil, err
			}
			tb.RawSetString(k, lv)
		}
		return tb, nil
	}
	return nil, fmt.Errorf("unsupported json value")
}
