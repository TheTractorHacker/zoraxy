package ech

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClassifyFallback(t *testing.T) {
	cases := []struct{ name, own, want string }{
		{"cloudflare-ech.com", "", FallbackForeignECH},
		{"Cloudflare-ECH.com.", "", FallbackForeignECH},
		{"public-ech.com", "", FallbackForeignECH},
		{"ech.example.com", "ech.example.com", FallbackOwnECH},
		{"ech.example.com", "", FallbackUnknown},
		{"scanner.example.net", "ech.example.com", FallbackUnknown},
		{"192.0.2.10", "", FallbackUnknown},
		{"echo.com", "", FallbackUnknown}, // ordinary name that merely contains "ech"
		{"", "ech.example.com", FallbackNoSNI},
	}
	for _, c := range cases {
		if got := ClassifyFallback(c.name, c.own); got != c.want {
			t.Errorf("ClassifyFallback(%q,%q)=%s want %s", c.name, c.own, got, c.want)
		}
	}
}

func TestFallbackTableCountsAndLogsOncePerHour(t *testing.T) {
	tb := NewFallbackTable()
	now := time.Unix(1_700_000_000, 0)
	tb.now = func() time.Time { return now }
	logs := 0
	for i := 0; i < 5; i++ {
		if l, c, _ := tb.Note("cloudflare-ech.com", ""); l {
			logs++
			if c != FallbackForeignECH {
				t.Fatal(c)
			}
		}
	}
	if logs != 1 {
		t.Fatalf("logged %d times within the hour", logs)
	}
	now = now.Add(61 * time.Minute)
	if l, _, _ := tb.Note("cloudflare-ech.com", ""); !l {
		t.Fatal("no log after an hour")
	}
	if l, _, _ := tb.Note("random.example", ""); l {
		t.Fatal("unknown hosts are never logged")
	}
	list, _ := tb.Snapshot()
	if len(list) != 2 || list[0].Name != "cloudflare-ech.com" || list[0].Count != 6 || list[0].FirstSeen >= list[0].LastSeen {
		t.Fatalf("snapshot %+v", list)
	}
	if !tb.HasForeignECH() {
		t.Fatal("HasForeignECH")
	}
	now = now.Add(8 * 24 * time.Hour)
	if l, _ := tb.Snapshot(); len(l) != 0 {
		t.Fatalf("idle entries must disappear: %+v", l)
	}
}

func TestFallbackTableIsBounded(t *testing.T) {
	tb := NewFallbackTable()
	now := time.Unix(1_700_000_000, 0)
	tb.now = func() time.Time { return now }
	for i := 0; i < 10000; i++ {
		now = now.Add(time.Second)
		tb.Note("h"+strconv.Itoa(i)+".example", "")
	}
	tb.Note(strings.Repeat("a", 5000)+"\x00\xff\n", "")
	list, dropped := tb.Snapshot()
	if len(list) > fallbackMaxEntries || dropped < 9000 {
		t.Fatalf("len=%d dropped=%d", len(list), dropped)
	}
	for _, e := range list {
		if len(e.Name) > fallbackMaxName {
			t.Fatalf("name too long: %d", len(e.Name))
		}
		for _, r := range e.Name {
			if r < 0x21 || r > 0x7e {
				t.Fatalf("unprintable name %q", e.Name)
			}
		}
	}
	// the most recent names survive, the oldest are gone
	found := false
	for _, e := range list {
		if e.Name == "h9999.example" {
			found = true
		}
		if e.Name == "h0.example" {
			t.Fatal("oldest entry kept")
		}
	}
	if !found {
		t.Fatal("newest entry lost")
	}
}
