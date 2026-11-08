package netutils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestIsMetadataAddress(t *testing.T) {
	for ip, want := range map[string]bool{
		"169.254.169.254":        true,
		"169.254.0.1":            true,
		"168.63.129.16":          true,
		"100.100.100.200":        true,
		"fd00:ec2::254":          true,
		"fe80::1":                true,
		"::ffff:169.254.169.254": true, //v4 mapped
		"10.0.0.1":               false,
		"192.168.1.1":            false,
		"127.0.0.1":              false,
		"8.8.8.8":                false,
		"168.63.129.17":          false,
		"2001:db8::1":            false,
	} {
		if got := IsMetadataAddress(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s = %v, want %v", ip, got, want)
		}
	}
}

func TestHTTPTest_RedirectChainAndTiming(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/middle", http.StatusFound) })
	mux.HandleFunc("/middle", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/end", http.StatusMovedPermanently) })
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test")
		w.Write([]byte("done"))
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	mux.HandleFunc("/evil", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := HTTPTest(context.Background(), srv.URL+"/start", "GET", true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hops) != 3 || res.Final != 200 {
		t.Fatalf("hops=%d final=%d: %+v", len(res.Hops), res.Final, res.Hops)
	}
	if res.Hops[0].Status != 302 || !strings.HasSuffix(res.Hops[0].Location, "/middle") || res.Hops[1].Status != 301 || res.Hops[2].Server != "test" {
		t.Fatalf("unexpected chain: %+v", res.Hops)
	}
	if res.Hops[0].RemoteAddr == "" || res.Hops[0].Proto == "" {
		t.Fatalf("missing connection details: %+v", res.Hops[0])
	}

	//Not following
	res, _ = HTTPTest(context.Background(), srv.URL+"/start", "HEAD", false, false, false)
	if len(res.Hops) != 1 || res.Final != 302 {
		t.Fatalf("no-follow: %+v", res)
	}

	//Loop ends at the redirect limit
	res, _ = HTTPTest(context.Background(), srv.URL+"/loop", "GET", true, false, false)
	if len(res.Hops) != 11 || res.Hops[len(res.Hops)-1].Error != "too many redirects" {
		t.Fatalf("loop: %d hops, last error %q", len(res.Hops), res.Hops[len(res.Hops)-1].Error)
	}

	//A redirect into the metadata range is refused at connect time
	res, _ = HTTPTest(context.Background(), srv.URL+"/evil", "GET", true, false, false)
	last := res.Hops[len(res.Hops)-1]
	if len(res.Hops) != 2 || !strings.Contains(last.Error, "metadata") {
		t.Fatalf("redirect to metadata was not blocked: %+v", res.Hops)
	}

	//Bad inputs
	for _, bad := range []struct{ url, method string }{
		{"ftp://example.com/", "GET"}, {"example.com", "GET"}, {"file:///etc/passwd", "GET"}, {"http://", "GET"}, {srv.URL, "DELETE"}, {srv.URL, "POST"},
	} {
		if _, err := HTTPTest(context.Background(), bad.url, bad.method, true, false, false); err == nil {
			t.Errorf("%q %q accepted", bad.url, bad.method)
		}
	}
}

func TestHTTPTest_DirectMetadataTargetsBlocked(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254:80/",
		"http://[fd00:ec2::254]/",
		"http://168.63.129.16/machine",
		"http://100.100.100.200/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/",
		"http://2852039166/", //decimal form of 169.254.169.254
		"http://0xa9fea9fe/", //hex form
	} {
		res, err := HTTPTest(context.Background(), target, "GET", false, false, false)
		if err != nil {
			continue //rejected before connecting is fine too
		}
		//Either blocked at connect time, or (decimal / hex IPv4 spellings) not resolvable by Go at all, so never connected
		if len(res.Hops) == 0 || !(strings.Contains(res.Hops[0].Error, "metadata") || strings.Contains(res.Hops[0].Error, "lookup")) {
			t.Errorf("%s was not blocked: %+v", target, res.Hops)
		}
	}
}

func TestInspectTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	res, err := InspectTLS(context.Background(), u.Hostname(), port, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chain) != 1 || res.Version == "" || res.CipherSuite == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Verified || res.VerifyError == "" {
		t.Error("the httptest certificate is self signed and must not verify")
	}
	if !res.Chain[0].SelfSigned || res.Chain[0].SHA256 == "" || res.Chain[0].DaysLeft < 1 {
		t.Errorf("cert details: %+v", res.Chain[0])
	}
	if !res.HostnameOK {
		t.Error("httptest certificate covers 127.0.0.1")
	}
	if _, err := InspectTLS(context.Background(), "127.0.0.1", 0, "", false); err == nil {
		t.Error("port 0 accepted")
	}
	if _, err := InspectTLS(context.Background(), "169.254.169.254", 443, "", false); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Errorf("metadata address not blocked: %v", err)
	}
	if _, err := InspectTLS(context.Background(), "bad host/", 443, "", false); err == nil {
		t.Error("invalid host accepted")
	}
}

func TestDNSLookup(t *testing.T) {
	res, err := DNSLookup(context.Background(), "localhost", []string{"A"}, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res[0].Records {
		if r == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Skipf("system resolver does not answer localhost: %+v", res)
	}
	for _, bad := range []struct {
		host   string
		types  []string
		server string
	}{
		{"", nil, ""}, {"bad host", nil, ""}, {"a/b", nil, ""}, {"user@host", nil, ""}, {"localhost", []string{"AXFR"}, ""},
		{"localhost", []string{"A"}, "not-an-ip"}, {"localhost", []string{"A"}, "dns.example.com:53"},
	} {
		if _, err := DNSLookup(context.Background(), bad.host, bad.types, bad.server); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
