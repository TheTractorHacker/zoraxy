package dynamicproxy

import "testing"

func TestMaskHeaderRuleSecretsDoesNotLeakOrMutate(t *testing.T) {
	pe := &ProxyEndpoint{HeaderRules: []*HeaderRule{
		{Name: "X-Key", Values: []string{"s3cret", "s3cret-2"}},
		{Name: "X-Re", Match: "regex", Values: []string{`a+`}},
	}}
	cp := CopyEndpoint(pe)
	cp.MaskHeaderRuleSecrets()
	for _, v := range cp.HeaderRules[0].Values {
		if v != "" {
			t.Fatalf("secret leaked: %q", v)
		}
	}
	if len(cp.HeaderRules[0].Values) != 2 || cp.HeaderRules[1].Values[0] != "a+" {
		t.Fatal("masking must keep the slot count and leave regex rules alone")
	}
	if pe.HeaderRules[0].Values[0] != "s3cret" {
		t.Fatal("masking changed the live rule")
	}
}
