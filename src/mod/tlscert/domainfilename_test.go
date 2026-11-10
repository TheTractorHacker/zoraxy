package tlscert

import "testing"

func TestDomainToFilenameNoDoubleDot(t *testing.T) {
	cases := []struct{ domain, ext, want string }{
		{"www.example.com", ".pem", "www.example.com.pem"},
		{"www.example.com", ".key", "www.example.com.key"},
		{"www.example.com", "pem", "www.example.com.pem"},
		{"*.example.com", ".pem", "_.example.com.pem"},
		{"  api.example.com ", ".key", "api.example.com.key"},
	}
	for _, c := range cases {
		if got := domainToFilename(c.domain, c.ext); got != c.want {
			t.Errorf("domainToFilename(%q,%q)=%q want %q", c.domain, c.ext, got, c.want)
		}
	}
}

func TestSanListAddsCommonName(t *testing.T) {
	dns, ips := sanList("www.example.com", nil)
	if len(dns) != 1 || dns[0] != "www.example.com" || len(ips) != 0 {
		t.Fatalf("cn alone must become a SAN, got %v %v", dns, ips)
	}
	dns, _ = sanList("www.example.com", []string{"WWW.example.com", "api.example.com"})
	if len(dns) != 2 {
		t.Fatalf("cn already listed (case-insensitive) must not be repeated, got %v", dns)
	}
	dns, ips = sanList("10.0.0.5", []string{"app.local"})
	if len(dns) != 1 || len(ips) != 1 {
		t.Fatalf("an IP common name goes to the IP list, got %v %v", dns, ips)
	}
}
