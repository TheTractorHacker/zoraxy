package access

import (
	"fmt"
	"math/rand"
	"testing"

	"imuslab.com/zoraxy/mod/netutils"
)

// legacyIsIPBlacklisted is the pre-#986 implementation, kept as the reference the indexed
// lookup must agree with: an O(n) scan re-parsing every entry on each request.
func legacyIsIPBlacklisted(list map[string]string, ipAddr string) bool {
	if _, ok := list[ipAddr]; ok {
		return true
	}
	for ipOrCIDR := range list {
		if netutils.MatchIpWildcard(ipAddr, ipOrCIDR) {
			return true
		}
		if netutils.MatchIpCIDR(ipAddr, ipOrCIDR) {
			return true
		}
	}
	return false
}

func randV4(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
}

func randV6(r *rand.Rand) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", r.Intn(4)+0x2000, r.Intn(3), r.Intn(3), r.Intn(65536), r.Intn(2), 0, r.Intn(2), r.Intn(65536))
}

// randEntry returns a random blacklist entry of every supported (and a few unsupported) forms.
func randEntry(r *rand.Rand) string {
	switch r.Intn(10) {
	case 0, 1:
		return randV4(r)
	case 2, 3, 4:
		return fmt.Sprintf("%s/%d", randV4(r), 8+r.Intn(25))
	case 5:
		return randV6(r)
	case 6:
		return fmt.Sprintf("%s/%d", randV6(r), 16+r.Intn(113))
	case 7:
		o := [4]string{fmt.Sprint(r.Intn(256)), fmt.Sprint(r.Intn(256)), fmt.Sprint(r.Intn(256)), fmt.Sprint(r.Intn(256))}
		for i := 0; i < 1+r.Intn(3); i++ {
			o[3-i] = "*"
		}
		return fmt.Sprintf("%s.%s.%s.%s", o[0], o[1], o[2], o[3])
	case 8:
		return []string{"garbage", "1.2.3", "1.2.3.4/33", "::ffff:10.0.0.0/104", "::ffff:1.2.3.4", "*.*.*.*", "0.0.0.0/0", "::/0", "1.2.*.4.5"}[r.Intn(9)]
	default:
		return fmt.Sprintf("%d.%d.0.0/16", r.Intn(4), r.Intn(4))
	}
}

func randProbe(r *rand.Rand, entries []string) string {
	switch r.Intn(8) {
	case 0:
		return randV6(r)
	case 1:
		return randV4(r) + "%eth0"
	case 2:
		return "::ffff:" + randV4(r)
	case 3:
		return []string{"", "garbage", "1.2.3", "::", "0.0.0.0", "fe80::1%eth0"}[r.Intn(6)]
	case 4, 5:
		// small address space so CIDRs and wildcards actually hit
		return fmt.Sprintf("%d.%d.%d.%d", r.Intn(4), r.Intn(4), r.Intn(256), r.Intn(256))
	case 6:
		if len(entries) > 0 {
			return entries[r.Intn(len(entries))]
		}
	}
	return randV4(r)
}

func ruleWithList(list map[string]string) *AccessRule {
	return &AccessRule{BlackListIP: &list, BlackListContryCode: &map[string]string{}}
}

// The index must give the same answer as the legacy linear scan on random data.
func TestBlacklistIndexMatchesLegacyScan(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		r := rand.New(rand.NewSource(seed))
		list := map[string]string{}
		var entries []string
		for i := 0; i < 1+r.Intn(300); i++ {
			e := randEntry(r)
			list[e] = "c-" + e
			entries = append(entries, e)
		}
		rule := ruleWithList(list)
		for i := 0; i < 3000; i++ {
			ip := randProbe(r, entries)
			want := legacyIsIPBlacklisted(list, ip)
			if got := rule.IsIPBlacklisted(ip); got != want {
				t.Fatalf("seed %d: IsIPBlacklisted(%q) = %v, legacy %v", seed, ip, got, want)
			}
			comment, err := rule.GetBlacklistedIPComment(ip)
			if (err == nil) != want {
				t.Fatalf("seed %d: GetBlacklistedIPComment(%q) err=%v, legacy match=%v", seed, ip, err, want)
			}
			if err == nil {
				// the comment must belong to an entry that really matches the IP
				var src string
				if _, err := fmt.Sscanf(comment, "c-%s", &src); err != nil || !legacyIsIPBlacklisted(map[string]string{comment[2:]: ""}, ip) {
					t.Fatalf("seed %d: comment %q for %q does not belong to a matching entry", seed, comment, ip)
				}
			}
		}
	}
}

// Changes to the list (copy on write via Add / Remove) are picked up.
func TestBlacklistIndexFollowsChanges(t *testing.T) {
	rule := &AccessRule{BlackListIP: &map[string]string{}, BlackListContryCode: &map[string]string{}}
	if rule.IsIPBlacklisted("10.1.2.3") {
		t.Fatal("empty list must not match")
	}
	// bypass SaveChanges (needs a controller) by replacing the map the way Add does
	rule.BlackListIP = &map[string]string{"10.0.0.0/8": "x"}
	if !rule.IsIPBlacklisted("10.1.2.3") {
		t.Fatal("new CIDR not picked up")
	}
	rule.BlackListIP = &map[string]string{}
	if rule.IsIPBlacklisted("10.1.2.3") {
		t.Fatal("removed CIDR still matches")
	}
}

func benchList(n int) (map[string]string, []string) {
	r := rand.New(rand.NewSource(7))
	list := make(map[string]string, n)
	for len(list) < n {
		switch r.Intn(3) {
		case 0:
			list[randV4(r)] = ""
		case 1:
			list[fmt.Sprintf("%s/%d", randV4(r), 16+r.Intn(17))] = ""
		default:
			list[fmt.Sprintf("%d.%d.%d.*", r.Intn(256), r.Intn(256), r.Intn(256))] = ""
		}
	}
	probes := make([]string, 1024)
	for i := range probes {
		probes[i] = randV4(r)
	}
	return list, probes
}

// 100k entries, probes mostly miss (the worst case for a scan)
func BenchmarkBlacklistLegacyScan100k(b *testing.B) {
	list, probes := benchList(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyIsIPBlacklisted(list, probes[i%len(probes)])
	}
}

func BenchmarkBlacklistIndexed100k(b *testing.B) {
	list, probes := benchList(100000)
	rule := ruleWithList(list)
	rule.IsIPBlacklisted("1.1.1.1") // build the index
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsIPBlacklisted(probes[i%len(probes)])
	}
}

// A bulk import swaps the whole list. The compiled lookup index must notice, or
// imported entries would silently not be enforced (fork #252 + #986 interaction).
func TestBulkEditIPListIsEnforcedByLookupIndex(t *testing.T) {
	c := newPublicIPTestController(t, true)
	rule, err := c.GetAccessRuleByID("default")
	if err != nil {
		t.Fatal(err)
	}
	rule.BlacklistEnabled = true

	// Warm the index on the (empty) list so a stale cache would be visible.
	if rule.IsIPBlacklisted("198.51.100.20") {
		t.Fatal("unexpected blacklist hit on empty list")
	}

	// Same-size swap: remove nothing, add exactly one, then replace with a different single entry.
	if err := rule.BulkEditIPList(IPListBlack, func(m map[string]string) error {
		m["198.51.100.20"] = "bulk"
		m["203.0.113.0/24"] = "bulk cidr"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !rule.IsIPBlacklisted("198.51.100.20") || !rule.IsIPBlacklisted("203.0.113.77") {
		t.Fatal("bulk-imported entries are not enforced: stale lookup index")
	}

	// Replace both entries with two different ones (same size) in one bulk edit.
	if err := rule.BulkEditIPList(IPListBlack, func(m map[string]string) error {
		clear(m)
		m["192.0.2.9"] = "new"
		m["2001:db8::/32"] = "new v6"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rule.IsIPBlacklisted("198.51.100.20") || rule.IsIPBlacklisted("203.0.113.77") {
		t.Fatal("removed entries are still enforced: stale lookup index")
	}
	if !rule.IsIPBlacklisted("192.0.2.9") || !rule.IsIPBlacklisted("2001:db8::1") {
		t.Fatal("replacement entries are not enforced: stale lookup index")
	}
}
