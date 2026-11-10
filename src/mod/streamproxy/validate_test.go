package streamproxy

import "testing"

func TestValidateAddress(t *testing.T) {
	good := []string{":29215", "0.0.0.0:22", "127.0.0.1:2222", "[::]:80", "example.com:443", "localhost:8080"}
	for _, a := range good {
		if _, _, err := ValidateAddress(a, true); err != nil {
			t.Errorf("%q should be valid: %v", a, err)
		}
	}
	bad := []string{"", "not an address", ":0", ":99999", "host", "bad host:80", "<b>x</b>:80", "a..b:80"}
	for _, a := range bad {
		if _, _, err := ValidateAddress(a, true); err == nil {
			t.Errorf("%q should be invalid", a)
		}
	}
	if _, _, err := ValidateAddress(":80", false); err == nil {
		t.Error("a target needs a host")
	}
}

func TestValidateConfig(t *testing.T) {
	m := &Manager{Configs: []*ProxyRelayInstance{{UUID: "a", Name: "ssh-bastion", ListeningAddress: ":2222", UseTCP: true}}}
	if err := m.validateConfig("", "other", ":2223", "10.0.0.1:22", true, false, false, false); err != nil {
		t.Fatal(err)
	}
	cases := map[string][5]interface{}{
		"empty name":     {"", ":2223", "10.0.0.1:22", true, false},
		"duplicate name": {"SSH-Bastion", ":2223", "10.0.0.1:22", true, false},
		"duplicate port": {"x", ":2222", "10.0.0.1:22", true, false},
		"no protocol":    {"x", ":2223", "10.0.0.1:22", false, false},
		"bad listen":     {"x", "not an address", "10.0.0.1:22", true, false},
		"bad target":     {"x", ":2223", "nope", true, false},
	}
	for name, c := range cases {
		if err := m.validateConfig("", c[0].(string), c[1].(string), c[2].(string), c[3].(bool), c[4].(bool), false, false); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	//UDP on the port of a TCP-only config is fine, and editing the config itself must not clash with itself
	if err := m.validateConfig("", "x", ":2222", "10.0.0.1:22", false, true, false, false); err != nil {
		t.Errorf("udp on a tcp port: %v", err)
	}
	if err := m.validateConfig("a", "ssh-bastion", ":2222", "10.0.0.1:22", true, false, false, false); err != nil {
		t.Errorf("self edit: %v", err)
	}
}
