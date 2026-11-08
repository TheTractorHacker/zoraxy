package luascript

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func run(t *testing.T, src string, lim Limits) (*Result, error) {
	t.Helper()
	s, err := Compile("t", src, lim, nil)
	if err != nil {
		return nil, err
	}
	return s.Run(context.Background(), &Request{
		Method: "GET", Path: "/hello", RawQuery: "a=1&b=x%20y&a=2", Host: "example.com", ClientIP: "10.1.2.3",
		RuleName: "example.com", RequestID: "rid1", Scheme: "https",
		Headers: map[string][]string{"User-Agent": {"curl/8"}, "X-Multi": {"a", "b"}},
	})
}

func mustRun(t *testing.T, src string) *Result {
	t.Helper()
	res, err := run(t, src, Limits{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return res
}

func TestRequestAndResponse(t *testing.T) {
	res := mustRun(t, `
response.status = 201
response.headers["X-Rule"] = request.rule
response.body = request.method .. " " .. request.path .. " " .. request.args.a .. "|" .. request.args.b .. "|" ..
  request.headers["user-agent"] .. "|" .. request.headers["x-multi"] .. "|" .. request.client_ip .. "|" .. request.request_id .. "|" .. request.scheme
`)
	if res.Status != 201 || string(res.Body) != "GET /hello 1|x y|curl/8|a, b|10.1.2.3|rid1|https" {
		t.Fatalf("got %d %q", res.Status, res.Body)
	}
	if len(res.Headers) != 1 || res.Headers[0] != [2]string{"X-Rule", "example.com"} || !res.Responded {
		t.Fatalf("headers %v responded=%v", res.Headers, res.Responded)
	}
}

func TestRespondStopsAndRedirect(t *testing.T) {
	res := mustRun(t, `respond(403, "no", "text/plain") error("unreachable")`)
	if res.Status != 403 || string(res.Body) != "no" || !res.Responded || res.Headers[0][1] != "text/plain" {
		t.Fatalf("%+v", res)
	}
	res = mustRun(t, `redirect("https://example.org/x", 301)`)
	if res.Status != 301 || res.Headers[0] != [2]string{"Location", "https://example.org/x"} {
		t.Fatalf("%+v", res)
	}
	if _, err := run(t, `redirect("https://x/\r\nSet-Cookie: a=b")`, Limits{}); err == nil {
		t.Fatal("CRLF in redirect accepted")
	}
	if _, err := run(t, `redirect("/x", 200)`, Limits{}); err == nil {
		t.Fatal("non-3xx redirect accepted")
	}
}

func TestHookContinuesWhenUntouched(t *testing.T) {
	res := mustRun(t, `request_header_set("X-Auth-User", "bob") request_header_del("Cookie")`)
	if res.Responded || len(res.ReqSet) != 1 || res.ReqSet[0] != [2]string{"X-Auth-User", "bob"} || res.ReqDel[0] != "Cookie" {
		t.Fatalf("%+v", res)
	}
	if _, err := run(t, `request_header_set("X\r\nEvil", "a")`, Limits{}); err == nil {
		t.Fatal("bad header name accepted")
	}
	if _, err := run(t, `request_header_set("Host", "evil")`, Limits{}); err == nil {
		t.Fatal("Host override accepted")
	}
}

func TestResponseValidation(t *testing.T) {
	for name, src := range map[string]string{
		"status":        `response.status = 99`,
		"status string": `response.status = "ok"`,
		"101":           `response.status = 101`,
		"header crlf":   `response.headers["X-A"] = "a\r\nB: c"`,
		"content-len":   `response.headers["Content-Length"] = "5"`,
		"body table":    `response.body = {}`,
		"big body":      `response.body = string.rep("x", 600000)`,
	} {
		if _, err := run(t, src, Limits{MaxResponseBytes: 512 * 1024}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHelpers(t *testing.T) {
	res := mustRun(t, `
local t = json.decode('{"a":[1,2,{"b":true}],"c":"d"}')
local enc = json.encode({x = 1, y = {1, 2, 3}})
response.body = table.concat({
  t.a[3].b and "T" or "F", t.c, enc,
  base64.encode("hello"), base64.decode("aGVsbG8="), hex.encode("ab"),
  crypto.sha256("abc"), crypto.hmac_sha256("key", "msg"),
  time.format(0, "2006-01-02"), url.escape("a b&c"), url.unescape("a%20b"),
  tostring(crypto.equals("a", "a")),
}, "|")
`)
	want := `T|d|{"x":1,"y":[1,2,3]}|aGVsbG8=|hello|6162|ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628|1970-01-01|a+b%26c|a b|true`
	if string(res.Body) != want {
		t.Fatalf("got\n%s\nwant\n%s", res.Body, want)
	}
	if res := mustRun(t, `local v, err = json.decode("{bad") response.body = tostring(v) .. err`); !strings.HasPrefix(string(res.Body), "nilinvalid json") {
		t.Fatal(string(res.Body))
	}
	if _, err := run(t, `local t = {} t.self = t json.encode(t)`, Limits{}); err == nil {
		t.Fatal("cyclic table encoded")
	}
	if _, err := run(t, `json.encode(function() end)`, Limits{}); err == nil {
		t.Fatal("function encoded")
	}
}

func TestPatterns(t *testing.T) {
	res := mustRun(t, `
local out = {}
local function add(...) out[#out+1] = table.concat({...}, ",") end
add(string.find("hello world", "o w"))
add(string.find("hello world", "(o)(%s)"))
add(string.match("key=value", "(%w+)=(%w+)"))
add(string.match("/users/42/edit", "^/users/(%d+)"))
add(string.gsub("hello world", "o", "0"))
add(string.gsub("abc", "%w", "%0%0"))
add(string.gsub("hello", "l+", function(m) return "[" .. m .. "]" end))
add(string.gsub("$name is $age", "%$(%w+)", {name = "bob", age = 7}))
for k, v in string.gmatch("a=1, b=2", "(%w+)=(%w+)") do add(k, v) end
add(string.match("  trim  ", "^%s*(.-)%s*$"))
add(string.match("THE (quick) fox", "%((%a+)%)"))
add(string.match("f(a(b)c)d", "%b()"))
add(string.find("abc", "b", 1, true))
add(string.match("2024-01-02", "(%d+)-(%d+)-(%d+)"))
add(("x"):rep(3), string.format("%5.2f|%s|%d", 3.14159, "s", 42))
add(string.match("hello", "()ll()"))
response.body = table.concat(out, ";")
`)
	want := "5,7;5,6,o, ;key,value;42;hell0 w0rld,2;aabbcc,3;he[ll]o,1;bob is 7,2;a,1;b,2;trim;quick;(a(b)c);2,2;2024,01,02;xxx, 3.14|s|42;3,5"
	if string(res.Body) != want {
		t.Fatalf("got\n%s\nwant\n%s", res.Body, want)
	}
}

func TestKVPersistsAcrossRuns(t *testing.T) {
	kv := NewKV()
	s, err := Compile("kv", `local n = kv.incr("hits") response.body = tostring(n) kv.set("s", "v", 60) if kv.get("s") ~= "v" then error("kv") end`, Limits{}, kv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		r, err := s.Run(context.Background(), &Request{})
		if err != nil || string(r.Body) != string(rune('0'+i)) {
			t.Fatalf("run %d: %v %+v", i, err, r)
		}
	}
	if kv.Len() != 2 {
		t.Fatalf("keys: %d", kv.Len())
	}
	//Limits
	if _, err := run(t, `for i = 1, 5000 do kv.set("k" .. i, "v") end`, Limits{Timeout: time.Second}); err == nil {
		t.Fatal("kv key limit not enforced")
	}
	if _, err := run(t, `kv.set("k", {})`, Limits{}); err == nil {
		t.Fatal("kv table value accepted")
	}
}

// ---- sandbox escape attempts ----

func TestNoDangerousGlobals(t *testing.T) {
	for _, g := range []string{"os", "io", "package", "debug", "require", "dofile", "loadfile", "load", "loadstring", "module",
		"getfenv", "setfenv", "collectgarbage", "print", "coroutine", "newproxy", "_printregs"} {
		res, err := run(t, `response.body = tostring(`+g+` == nil)`, Limits{})
		if err != nil || string(res.Body) != "true" {
			t.Errorf("global %s is reachable (%v)", g, err)
		}
	}
	for _, g := range []string{"_G", "_ENV"} {
		_ = g
	}
	//Reaching them through _G or metatables must not work either
	res := mustRun(t, `local n = 0 for k in pairs(_G) do n = n + 1 end local hit = {} for _, name in ipairs({"os","io","require","load","loadstring","dofile","debug","package"}) do if rawget(_G, name) ~= nil then hit[#hit+1] = name end end response.body = table.concat(hit, ",")`)
	if len(res.Body) != 0 {
		t.Fatalf("leaked: %s", res.Body)
	}
}

func TestEscapeAttempts(t *testing.T) {
	marker := t.TempDir() + "/pwned"
	attempts := map[string]string{
		"os.execute":      `os.execute("touch ` + marker + `")`,
		"os.getenv":       `return os.getenv("HOME")`,
		"io.open":         `local f = io.open("/etc/passwd") return f:read("*a")`,
		"io.popen":        `io.popen("id")`,
		"require":         `require("os")`,
		"loadstring":      `loadstring("return os")()`,
		"load":            `load("return 1")()`,
		"dofile":          `dofile("/etc/passwd")`,
		"debug":           `debug.getinfo(1)`,
		"package.loaded":  `package.loaded.os.execute("x")`,
		"getfenv":         `getfenv(0).os.execute("x")`,
		"string.dump":     `string.dump(function() end)`,
		"metatable":       `getmetatable("").__index.os.execute("x")`,
		"setmetatable _G": `setmetatable(_G, {__index = function(_, k) return k end}) return os.execute()`,
	}
	for name, src := range attempts {
		if _, err := run(t, src, Limits{}); err == nil {
			t.Errorf("%s: escape attempt did not fail", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("os.execute created a file")
	}
}

func TestPrecompiledAndHugeSource(t *testing.T) {
	if _, err := Compile("x", "\x1bLua\x51\x00", Limits{}, nil); err == nil {
		t.Fatal("precompiled chunk accepted")
	}
	if _, err := Compile("x", strings.Repeat("a = 1\n", 20000), Limits{}, nil); err == nil {
		t.Fatal("source over the cap accepted")
	}
	//loadstring of huge code cannot be reached at all (no loadstring), and the source cap holds for the script itself
	if _, err := Compile("x", `x = (`, Limits{}, nil); err == nil {
		t.Fatal("syntax error not reported")
	}
}

func TestInfiniteLoopTimesOut(t *testing.T) {
	for name, src := range map[string]string{
		"while":     `while true do end`,
		"tailcall":  `local function f() return f() end return f()`,
		"pcall":     `while true do pcall(function() while true do end end) end`,
		"table":     `local t = {} while true do t[#t+1] = 1 end`,
		"sort":      `local t = {} for i = 1, 100000 do t[i] = i end table.sort(t, function(a, b) while true do end end)`,
		"gsub loop": `local s = ("a"):rep(1000) while true do s:gsub("a", "b") end`,
	} {
		start := time.Now()
		_, err := run(t, src, Limits{Timeout: 100 * time.Millisecond})
		if !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrMemory) {
			t.Errorf("%s: want timeout/memory error, got %v", name, err)
		}
		if d := time.Since(start); d > 1200*time.Millisecond {
			t.Errorf("%s: took %v", name, d)
		}

	}
	for i := 0; i < 200 && Abandoned() != 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if Abandoned() != 0 {
		t.Fatalf("%d runs were abandoned", Abandoned())
	}
}

func TestDeepRecursion(t *testing.T) {
	_, err := run(t, `local function f(n) return 1 + f(n + 1) end return f(1)`, Limits{Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("want stack overflow, got %v", err)
	}
	if _, err := run(t, `local t = {} for i = 1, 100000 do t[i] = i end local a = {unpack(t)} response.body = #a`, Limits{Timeout: time.Second}); err == nil {
		t.Fatal("unpack of 100000 values accepted")
	}
}

func TestMemoryBombs(t *testing.T) {
	if _, err := run(t, `local s = string.rep("x", 1e9)`, Limits{}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("string.rep bomb: %v", err)
	}
	if _, err := run(t, `local s = string.rep("x", 1e6) local t = string.rep(s, 1e6)`, Limits{}); err == nil {
		t.Fatal("nested rep bomb accepted")
	}
	if _, err := run(t, `return string.format("%99999999d", 1)`, Limits{}); err == nil {
		t.Fatal("format width bomb accepted")
	}
	//Doubling a string with the concat operator is not capped per operation: the heap watchdog / deadline stops it
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := run(t, `local s = string.rep("x", 1000000) while true do s = s .. s end`, Limits{Timeout: 2 * time.Second, MaxHeapGrowth: 64 << 20})
	if !errors.Is(err, ErrMemory) && !errors.Is(err, ErrTimeout) {
		t.Fatalf("concat bomb: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("concat bomb not stopped in time")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc+256<<20 {
		t.Fatalf("heap not released after the bomb: %d -> %d", before.HeapAlloc, after.HeapAlloc)
	}
	//table bomb
	if _, err := run(t, `local t = {} for i = 1, 1e9 do t[i] = {i, i, i, i} end`, Limits{Timeout: 2 * time.Second, MaxHeapGrowth: 32 << 20}); !errors.Is(err, ErrMemory) && !errors.Is(err, ErrTimeout) {
		t.Fatalf("table bomb: %v", err)
	}
}

func TestPatternCatastrophe(t *testing.T) {
	start := time.Now()
	_, err := run(t, `return string.find(string.rep("a", 3000), "a*a*a*a*a*a*b")`, Limits{Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Fatalf("catastrophic pattern: %v", err)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("pattern budget did not stop the match quickly")
	}
	if _, err := run(t, `return string.find("a", string.rep("a?", 200))`, Limits{}); err == nil {
		t.Fatal("pattern over the length cap accepted")
	}
	if _, err := run(t, `return string.find("abc", "[a")`, Limits{}); err == nil {
		t.Fatal("malformed pattern accepted")
	}
}

func TestPanicRecovered(t *testing.T) {
	//Unsafe conversions inside natives must not take down the process: here a Go panic is simulated through a bad argument
	_, err := run(t, `string.rep()`, Limits{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConcurrencyPoolBusy(t *testing.T) {
	s, err := Compile("busy", `while true do end`, Limits{Timeout: 300 * time.Millisecond, Concurrency: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var busy, timeouts int32
	var mu sync.Mutex
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Run(context.Background(), &Request{})
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, ErrBusy) {
				busy++
			} else if errors.Is(err, ErrTimeout) {
				timeouts++
			}
		}()
	}
	wg.Wait()
	if busy == 0 || timeouts == 0 {
		t.Fatalf("expected both busy and timeout results, got busy=%d timeout=%d", busy, timeouts)
	}
}

func TestConcurrentRunsAreIsolated(t *testing.T) {
	s, err := Compile("iso", `counter = (counter or 0) + 1 response.body = tostring(counter)`, Limits{Concurrency: 16}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.Run(context.Background(), &Request{})
			if err != nil || string(r.Body) != "1" {
				t.Errorf("globals leaked between runs: %v %v", err, r)
			}
		}()
	}
	wg.Wait()
}

func TestCancelledParent(t *testing.T) {
	s, _ := Compile("c", `while true do end`, Limits{Timeout: 2 * time.Second}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := s.Run(ctx, &Request{})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("client cancel not honoured: %v after %v", err, time.Since(start))
	}
}
