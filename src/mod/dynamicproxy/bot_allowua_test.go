package dynamicproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/botrules"
)

func TestBotAllowUASkipsOnlyOnThisSite(t *testing.T) {
	router, sep, _ := newBotRouter(t, func(c *botrules.Config) {
		c.Categories["http_library"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionBlock}
	})
	other := CopyEndpoint(sep)
	other.BotAllowUA = nil
	sep.BotAllowUA = []string{"curl/"}
	if w := serveUA(router, sep, "curl/8.18.0"); w.Code != 299 {
		t.Fatalf("allowed UA still judged on its site: %d", w.Code)
	}
	if w := serveUA(router, other, "curl/8.18.0"); w.Code != 403 {
		t.Fatalf("allow list leaked to another site: %d", w.Code)
	}
	// case-insensitive on both sides
	if w := serveUA(router, sep, "CURL/7.1"); w.Code != 299 {
		t.Fatalf("match is case sensitive: %d", w.Code)
	}
	sep.BotAllowUA = []string{"CuRl/"}
	if w := serveUA(router, sep, "curl/8"); w.Code != 299 {
		t.Fatalf("hand-edited upper case entry ignored: %d", w.Code)
	}
	// other bots on the same site are still judged
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 403 {
		t.Fatalf("scanner skipped by an unrelated entry: %d", w.Code)
	}
	if w := serveUA(router, sep, "python-requests/2.31"); w.Code != 403 {
		t.Fatalf("other http library skipped: %d", w.Code)
	}
	// a second User-Agent header must not smuggle a bot behind an allowed one
	if w := serveWithHeaders(router, sep, "/", map[string][]string{"User-Agent": {"curl/8", "sqlmap"}}); w.Code != 403 {
		t.Fatalf("bot hidden behind an allowed first header: %d", w.Code)
	}
	if w := serveWithHeaders(router, sep, "/", map[string][]string{"User-Agent": {"curl/8", "curl/7"}}); w.Code != 299 {
		t.Fatalf("all values allowed but judged: %d", w.Code)
	}
}

func TestOldConfigWithoutBotAllowUALoads(t *testing.T) {
	var ep ProxyEndpoint
	if err := json.Unmarshal([]byte(`{"ProxyType":1,"RootOrMatchingDomain":"a.example.com","BotPolicy":"on"}`), &ep); err != nil {
		t.Fatal(err)
	}
	if ep.BotAllowUA != nil || ep.BotPolicy != "on" {
		t.Fatalf("%v %q", ep.BotAllowUA, ep.BotPolicy)
	}
	js, _ := json.Marshal(&ep)
	if strings.Contains(string(js), "BotAllowUA") {
		t.Fatalf("an empty list must not be written: %s", js)
	}
	ep.BotAllowUA = []string{"curl/"}
	js, _ = json.Marshal(&ep)
	var back ProxyEndpoint
	if err := json.Unmarshal(js, &back); err != nil || len(back.BotAllowUA) != 1 || back.BotAllowUA[0] != "curl/" {
		t.Fatalf("round trip: %v %+v", err, back.BotAllowUA)
	}
}
