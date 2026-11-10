package main

import "testing"

func TestValidateTrustedProxyEntry(t *testing.T) {
	good := []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "::1", "203.0.113.0/24"}
	bad := []string{"abc", "999.1.1.1", "1.2.3.4/99", "0.0.0.0/0", "::/0", "garbage line", "1.2.3.4/"}
	for _, v := range good {
		if err := validateTrustedProxyEntry(v); err != nil {
			t.Errorf("%q should be accepted: %v", v, err)
		}
	}
	for _, v := range bad {
		if err := validateTrustedProxyEntry(v); err == nil {
			t.Errorf("%q should be rejected", v)
		}
	}
}
