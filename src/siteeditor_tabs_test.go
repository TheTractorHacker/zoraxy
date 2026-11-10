package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The proxy rule editor offers the classic 11 tabs and five sections over the same cards (docs/ux/site-editor.md).
// The browser test (tools/ui-smoke/editortabs_smoke.py) checks the behaviour; these tests pin the static data it relies on,
// so a card that is added or moved without its tab fails fast, without a browser.

var classicTabs = []string{"downstream", "upstream", "vdirs", "websocket", "alias", "ssl", "headers", "accessrule", "security", "waf", "tags"}
var classicLabels = []string{"Host", "Destinations", "Virtual Directory", "WebSocket", "Alias", "TLS / SSL", "Headers", "Access Rules", "Security", "WAF", "Tags"}

type editorCard struct {
	name, tab string
	ord       int
	easyOnly  bool
}

func readEditorCards(t *testing.T) (map[string]editorCard, string) {
	t.Helper()
	b, err := os.ReadFile("web/components/httprp.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	re := regexp.MustCompile(`<section class="zx-card hrp-card" data-hrp-card="([a-z]+)"([^>]*)>`)
	attr := func(s, n string) string {
		m := regexp.MustCompile(n + `="([^"]*)"`).FindStringSubmatch(s)
		if m == nil {
			return ""
		}
		return m[1]
	}
	cards := map[string]editorCard{}
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		ord, _ := strconv.Atoi(attr(m[2], "data-hrp-ord"))
		cards[m[1]] = editorCard{name: m[1], tab: attr(m[2], "data-hrp-tab"), ord: ord,
			easyOnly: regexp.MustCompile(`data-hrp-easyonly`).MatchString(m[2])}
	}
	if len(cards) < 25 {
		t.Fatalf("found only %d cards in httprp.html", len(cards))
	}
	return cards, html
}

func TestEditorEveryCardHasAClassicTab(t *testing.T) {
	cards, _ := readEditorCards(t)
	valid := map[string]bool{}
	for _, n := range classicTabs {
		valid[n] = true
	}
	seen := map[string]map[int]string{}
	for _, c := range cards {
		if c.tab == "" {
			if !c.easyOnly {
				t.Errorf("card %s has no data-hrp-tab: it would be unreachable in the Tabs layout", c.name)
			}
			continue
		}
		if !valid[c.tab] {
			t.Errorf("card %s is on unknown tab %q", c.name, c.tab)
		}
		if c.ord < 0 || (c.ord == 0 && c.name != "protection") {
			t.Errorf("card %s has a bad data-hrp-ord %d", c.name, c.ord)
		}
		if seen[c.tab] == nil {
			seen[c.tab] = map[int]string{}
		}
		if other, dup := seen[c.tab][c.ord]; dup {
			t.Errorf("cards %s and %s share position %d on tab %s", other, c.name, c.ord, c.tab)
		}
		seen[c.tab][c.ord] = c.name
	}
	for _, n := range classicTabs {
		if len(seen[n]) == 0 {
			t.Errorf("tab %s has no card", n)
		}
	}
}

// Every control of the old 11-tab editor (siteeditor_inventory.json, generated from the markup before the redesign)
// lives in a card that sits on the tab the control had.
func TestEditorInventoryMatchesClassicTabs(t *testing.T) {
	cards, _ := readEditorCards(t)
	b, err := os.ReadFile("../tools/ui-smoke/siteeditor_inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv []struct {
		Selector string `json:"selector"`
		OldTab   string `json:"oldTab"`
		Card     string `json:"card"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range inv {
		if e.Card == "" {
			continue
		}
		c, ok := cards[e.Card]
		if !ok {
			t.Errorf("%s: card %q does not exist", e.Selector, e.Card)
			continue
		}
		if c.tab != e.OldTab {
			t.Errorf("%s was on the %q tab of the old editor, its card %s is on %q", e.Selector, e.OldTab, e.Card, c.tab)
		}
		checked++
	}
	if checked < 100 {
		t.Errorf("only %d inventory controls checked", checked)
	}
}

// The tab strip is rendered by siteeditor.js: names (the old cfgpage values) and labels in the order of the old editor,
// Tabs is the default layout and the choice lives in its own localStorage key (the Easy / Advanced key is not reused).
func TestEditorTabsScript(t *testing.T) {
	b, err := os.ReadFile("web/script/siteeditor.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	start := regexp.MustCompile(`var TABS = \[`).FindStringIndex(js)
	if start == nil {
		t.Fatal("TABS list not found")
	}
	end := regexp.MustCompile(`\];`).FindStringIndex(js[start[0]:])
	block := js[start[0] : start[0]+end[1]]
	re := regexp.MustCompile(`name: "([a-z]+)", icon: "[a-z ]+", label: function \(\) \{ return t\("([^"]+)"\); \}`)
	ms := re.FindAllStringSubmatch(block, -1)
	if len(ms) != len(classicTabs) {
		t.Fatalf("TABS has %d entries, want %d", len(ms), len(classicTabs))
	}
	for i, m := range ms {
		if m[1] != classicTabs[i] || m[2] != classicLabels[i] {
			t.Errorf("tab %d is %s/%q, want %s/%q", i, m[1], m[2], classicTabs[i], classicLabels[i])
		}
	}
	for _, want := range []string{
		`var LAYOUT_KEY = "zoraxy_site_editor_layout";`,
		`var MODE_KEY = "zoraxy_site_editor_mode";`,
		`localStorage.getItem(LAYOUT_KEY) === "sections" ? "sections" : "tabs"`,
		`catch (e) { return "tabs"; }`,
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(js) {
			t.Errorf("siteeditor.js lacks %q", want)
		}
	}
	_, html := readEditorCards(t)
	if !regexp.MustCompile(`id="httprpEditModal"[^>]*data-layout="tabs"`).MatchString(html) {
		t.Error("the markup must start in the Tabs layout")
	}
}
