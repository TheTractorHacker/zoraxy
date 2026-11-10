package cluster

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

/*
	Snapshot format

	A snapshot is a JSON envelope:

	  {format, v, version, createdAt, node, nonce, data, sig}

	data is AES-256-GCM(gzip(JSON payload)) and sig is HMAC-SHA256 over the
	header fields and the ciphertext. Keys are derived from the cluster
	secret with HKDF (separate keys for signing and encryption). The set of
	files that can ever be included is an allow-list (see managedRoots), so
	node specific data (sys.uuid, admin accounts, admin TLS certificate,
	updater state, logs) is excluded by construction.
*/

const (
	snapshotFormat    = "zoraxy-cluster-snapshot"
	snapshotVersionNo = 1

	// MaxSnapshotBytes bounds the decoded payload (zip bomb guard) and the
	// transferred envelope.
	MaxSnapshotBytes = 256 << 20
)

// Roots (relative to the conf folder) that may be synced. Everything else in
// the conf folder is node specific and never leaves the node.
var baseRoots = []string{
	"proxy",
	"redirect",
	"access",
	"streamproxy",
	"rules",
	"trusted_proxies.json",
	"acme_conf.json",
	"waf_central.json",
	"ruleset",
}

const certRoot = "certs"

// ManagedRoots returns the roots covered by a snapshot.
func ManagedRoots(includeCerts bool) []string {
	r := append([]string{}, baseRoots...)
	if includeCerts {
		r = append(r, certRoot)
	}
	return r
}

// FileEntry is one file in a snapshot. Path is relative to the conf folder,
// slash separated.
type FileEntry struct {
	Path string `json:"p"`
	Mode uint32 `json:"m"`
	Data []byte `json:"d"`
}

// Payload is the decrypted content of a snapshot.
type Payload struct {
	Roots         []string    `json:"roots"`
	IncludesCerts bool        `json:"includesCerts"`
	ContentHash   string      `json:"hash"`
	Files         []FileEntry `json:"files"`
	// Fleet carries bundle metadata of the central management mode (nil for
	// the legacy primary/follower snapshots).
	Fleet *FleetMeta `json:"fleet,omitempty"`
}

// Envelope is the transferred form.
type Envelope struct {
	Format    string `json:"format"`
	V         int    `json:"v"`
	Version   int64  `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	Node      string `json:"node"`
	Nonce     string `json:"nonce"`
	Data      string `json:"data"`
	Sig       string `json:"sig"`
}

// Errors returned by Open.
var (
	ErrBadSignature = errors.New("snapshot signature invalid (wrong cluster secret or tampered data)")
	ErrBadFormat    = errors.New("snapshot format not recognised")
)

// CollectFiles reads the syncable files from a conf folder. Symlinks and
// non-regular files are skipped.
func CollectFiles(confDir string, includeCerts bool) (*Payload, error) {
	p := &Payload{Roots: ManagedRoots(includeCerts), IncludesCerts: includeCerts}
	var total int64
	for _, root := range p.Roots {
		abs := filepath.Join(confDir, filepath.FromSlash(root))
		fi, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		add := func(file string, info fs.FileInfo) error {
			rel, err := filepath.Rel(confDir, file)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !validEntryPath(rel, p.Roots) {
				return nil //not part of the allow-list (e.g. proxy/*.bak)
			}
			total += info.Size()
			if total > MaxSnapshotBytes {
				return errors.New("snapshot too large")
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			p.Files = append(p.Files, FileEntry{Path: rel, Mode: uint32(info.Mode().Perm()), Data: data})
			return nil
		}
		if fi.Mode().IsRegular() {
			if err := add(abs, fi); err != nil {
				return nil, err
			}
			continue
		}
		if !fi.IsDir() {
			continue
		}
		err = filepath.WalkDir(abs, func(file string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() { //skips dirs, symlinks, sockets
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return add(file, info)
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Path < p.Files[j].Path })
	p.ContentHash = HashFiles(p.Files)
	return p, nil
}

// HashFiles computes the content hash over paths and data (not modes).
func HashFiles(files []FileEntry) string {
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(strconv.Itoa(len(f.Data))))
		h.Write([]byte{0})
		h.Write(f.Data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validEntryPath is the single gatekeeper for paths on both the collect and
// the apply side: relative, clean, slash separated, inside a managed root.
func validEntryPath(p string, roots []string) bool {
	if p == "" || strings.ContainsAny(p, "\\\x00") || path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	parts := strings.Split(p, "/")
	for _, s := range parts {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	rootOK := false
	for _, r := range roots {
		if parts[0] == r {
			rootOK = true
			break
		}
	}
	if !rootOK {
		return false
	}
	switch parts[0] {
	case "proxy":
		return len(parts) == 2 && strings.HasSuffix(parts[1], ".config")
	case "trusted_proxies.json", "acme_conf.json", "waf_central.json":
		return len(parts) == 1
	default:
		return len(parts) >= 2
	}
}

// ValidatePayload checks every entry and that JSON-ish files parse, so a
// broken snapshot is rejected before anything is touched.
func ValidatePayload(p *Payload) error {
	if p == nil {
		return errors.New("empty payload")
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if !validEntryPath(f.Path, p.Roots) {
			return fmt.Errorf("snapshot contains an invalid path %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("snapshot contains duplicate path %q", f.Path)
		}
		seen[f.Path] = true
		if strings.HasSuffix(f.Path, ".config") || strings.HasSuffix(f.Path, ".json") {
			if !json.Valid(f.Data) {
				return fmt.Errorf("snapshot file %q is not valid JSON", f.Path)
			}
		}
	}
	for _, r := range p.Roots {
		okRoot := false
		for _, a := range ManagedRoots(true) {
			if r == a {
				okRoot = true
			}
		}
		if !okRoot {
			return fmt.Errorf("snapshot declares unknown root %q", r)
		}
	}
	if HashFiles(p.Files) != p.ContentHash {
		return errors.New("snapshot content hash mismatch")
	}
	return nil
}

func header(e *Envelope) []byte {
	return []byte(fmt.Sprintf("zcs%d|%d|%d|%s|%s", e.V, e.Version, e.CreatedAt, e.Node, e.Nonce))
}

func gcmFor(secret string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(DeriveKey(secret, PurposeSyncEncrypt, 32))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sign(secret string, hdr, ciphertext []byte) string {
	m := hmac.New(sha256.New, DeriveKey(secret, PurposeSyncSign, 32))
	m.Write(hdr)
	m.Write([]byte{0})
	m.Write(ciphertext)
	return hex.EncodeToString(m.Sum(nil))
}

// Seal encodes, encrypts and signs a payload.
func Seal(secret string, version, createdAt int64, node string, p *Payload) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	gcm, err := gcmFor(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	env := &Envelope{
		Format: snapshotFormat, V: snapshotVersionNo, Version: version,
		CreatedAt: createdAt, Node: node,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}
	ct := gcm.Seal(nil, nonce, zbuf.Bytes(), header(env))
	env.Data = base64.StdEncoding.EncodeToString(ct)
	env.Sig = sign(secret, header(env), ct)
	return json.Marshal(env)
}

// Open verifies the signature (constant time), then decrypts and validates a
// snapshot. The envelope metadata is returned even when later steps fail only
// if the signature was good.
func Open(secret string, raw []byte) (*Envelope, *Payload, error) {
	if len(raw) > MaxSnapshotBytes*2 {
		return nil, nil, errors.New("snapshot too large")
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, ErrBadFormat
	}
	if env.Format != snapshotFormat || env.V != snapshotVersionNo {
		return nil, nil, ErrBadFormat
	}
	ct, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, nil, ErrBadFormat
	}
	want, err := hex.DecodeString(env.Sig)
	if err != nil {
		return nil, nil, ErrBadSignature
	}
	got, _ := hex.DecodeString(sign(secret, header(&env), ct))
	if !hmac.Equal(got, want) {
		return nil, nil, ErrBadSignature
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, nil, ErrBadFormat
	}
	gcm, err := gcmFor(secret)
	if err != nil {
		return nil, nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, nil, ErrBadFormat
	}
	zdata, err := gcm.Open(nil, nonce, ct, header(&env))
	if err != nil {
		return nil, nil, ErrBadSignature
	}
	zr, err := gzip.NewReader(bytes.NewReader(zdata))
	if err != nil {
		return nil, nil, ErrBadFormat
	}
	plain, err := io.ReadAll(io.LimitReader(zr, MaxSnapshotBytes+1))
	if err != nil || len(plain) > MaxSnapshotBytes {
		return nil, nil, errors.New("snapshot payload invalid or too large")
	}
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, nil, ErrBadFormat
	}
	if err := ValidatePayload(&p); err != nil {
		return nil, nil, err
	}
	return &env, &p, nil
}
