package forward

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Upstream #816: "memory overflow with false forward-auth redirect (Authelia)". Hammer a forward-auth
// protected rule whose auth server always answers 302/401 (with a large body) and check that goroutines
// and heap do not grow. ZORAXY_LEAK_SECONDS raises the duration (default 4s) for a longer soak.
func TestForwardAuthAlwaysRedirectDoesNotLeak(t *testing.T) {
	secs := 4
	if v, err := strconv.Atoi(os.Getenv("ZORAXY_LEAK_SECONDS")); err == nil && v > 0 {
		secs = v
	}
	big := strings.Repeat("x", 256<<10) // 256 KiB body that must not be buffered or retained
	var flip int
	var mu sync.Mutex
	au := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		flip++
		f := flip
		mu.Unlock()
		if f%2 == 0 {
			w.Header().Set("Location", "https://auth.example.com/?rd="+r.Header.Get("X-Forwarded-Uri"))
			w.WriteHeader(302)
		} else {
			w.WriteHeader(401)
		}
		w.Write([]byte(big))
	}))
	defer au.Close()
	ar := newTestRouter(t, func(o *AuthRouterOptions) { o.Address = au.URL + "/api/verify" })

	run := func(d time.Duration) int {
		var wg sync.WaitGroup
		var n int
		var nm sync.Mutex
		stop := time.Now().Add(d)
		for g := 0; g < 16; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(stop) {
					r := httptest.NewRequest("GET", "http://app.example.com/some/page?x=1", nil)
					w := httptest.NewRecorder()
					if err := ar.HandleAuthProviderRouting(w, r); err != ErrUnauthorized {
						t.Errorf("got %v", err)
						return
					}
					nm.Lock()
					n++
					nm.Unlock()
				}
			}()
		}
		wg.Wait()
		return n
	}

	run(time.Second) // warm up pools / keep-alive connections
	au.CloseClientConnections()
	settle := func() (int, uint64) {
		time.Sleep(300 * time.Millisecond)
		runtime.GC()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return runtime.NumGoroutine(), ms.HeapAlloc
	}
	g0, h0 := settle()
	n := run(time.Duration(secs) * time.Second)
	au.CloseClientConnections()
	g1, h1 := settle()
	t.Logf("requests=%d goroutines %d -> %d, heap %d KiB -> %d KiB", n, g0, g1, h0>>10, h1>>10)
	if g1 > g0+10 {
		t.Fatalf("goroutine leak: %d -> %d", g0, g1)
	}
	if h1 > h0+16<<20 {
		t.Fatalf("heap grew from %d to %d bytes after %d requests", h0, h1, n)
	}
}
