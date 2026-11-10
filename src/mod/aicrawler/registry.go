// Package aicrawler is the AI crawler policy of proxied sites: a curated, versioned registry
// of known AI user agents grouped by purpose, a per group / per crawler / per site policy
// (allow, block, challenge, rate limit, log only), optional verification of the claimed
// identity (published IP ranges or forward-confirmed reverse DNS), and generated robots.txt /
// llms.txt text.
//
// Everything is off by default. While the policy is off, or while a crawler has no policy,
// the existing behaviour (the "AI crawlers" switch of a proxy rule, the Security Center bot
// rules, the WAF) is unchanged. A User-Agent is a claim, not a proof: only the verification
// (where the operator publishes a method) tells a real crawler from an imitation.
package aicrawler

import "strings"

// RegistryVersion is bumped whenever an entry, a group or a verification source changes.
const RegistryVersion = "2026.11.1"

// Group ids (purpose of the crawler)
const (
	GroupTraining = "training" // collects content to train models
	GroupSearch   = "search"   // builds a search / answer index, links back to the site
	GroupAgent    = "agent"    // fetches a page because a person asked an assistant to
)

// GroupInfo describes a group for the UI
type GroupInfo struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

// Groups lists the groups in display order
func Groups() []GroupInfo {
	return []GroupInfo{
		{GroupTraining, "Training", "Collects pages to train or improve AI models. Blocking it keeps your content out of future training data."},
		{GroupSearch, "Search and indexing", "Builds the index an AI search product answers from. Usually sends visitors back to you."},
		{GroupAgent, "User-triggered fetch", "Fetches one page because a person asked an assistant to (for example by pasting a link). Behaves like a browser."},
	}
}

// Source is a published IP range list the operator documents for one crawler
type Source struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Sources is the allow-list of range lists that may be refreshed. Only these exact URLs are ever fetched.
// No address range is shipped with Zoraxy: the data comes from the operators, when the admin presses Refresh.
func Sources() []Source {
	return []Source{
		{"openai-gptbot", "https://openai.com/gptbot.json"},
		{"openai-searchbot", "https://openai.com/searchbot.json"},
		{"openai-chatgpt-user", "https://openai.com/chatgpt-user.json"},
		{"perplexity-bot", "https://www.perplexity.com/perplexitybot.json"},
		{"perplexity-user", "https://www.perplexity.com/perplexity-user.json"},
		{"amazonbot", "https://developer.amazon.com/amazonbot/live-ip-addresses.json"},
		{"commoncrawl-ccbot", "https://index.commoncrawl.org/ccbot.json"},
	}
}

// Verify is the documented way to tell the real crawler from an imitation. Empty = the operator
// publishes none, so the identity cannot be verified.
type Verify struct {
	RangeSources []string `json:"rangeSources,omitempty"` // Source ids; the client address must be inside one of them
	RDNSSuffixes []string `json:"rdnsSuffixes,omitempty"` // forward-confirmed reverse DNS must end with one of these
}

// Verifiable reports whether the operator documents any method
func (v Verify) Verifiable() bool { return len(v.RangeSources) > 0 || len(v.RDNSSuffixes) > 0 }

// Entry is one known crawler
type Entry struct {
	ID        string `json:"id"`        // stable key used in the configuration
	Name      string `json:"name"`      // product token as the operator writes it
	Operator  string `json:"operator"`  //
	Group     string `json:"group"`     // training | search | agent
	Purpose   string `json:"purpose"`   // one sentence
	UA        string `json:"ua"`        // lowercase substring of the User-Agent header; empty for token-only entries
	Token     string `json:"token"`     // robots.txt user-agent token
	TokenOnly bool   `json:"tokenOnly"` // a robots.txt control token: no request ever carries it, so it cannot be enforced
	Verify    Verify `json:"verify"`
	Note      string `json:"note,omitempty"`
	Docs      string `json:"docs,omitempty"`
}

// Registry returns the curated list (a copy). It is deliberately conservative: link preview
// fetchers (facebookexternalhit, Slackbot, ...) and classic search engines (Googlebot, Bingbot) are not AI crawlers
// and are not in it.
func Registry() []Entry {
	out := make([]Entry, len(registry))
	copy(out, registry)
	return out
}

// Lookup finds an entry by id
func Lookup(id string) (Entry, bool) {
	for _, e := range registry {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

const anthropicNoIP = "Anthropic does not publish IP ranges, so this crawler cannot be verified by address."

var registry = []Entry{
	{ID: "gptbot", Name: "GPTBot", Operator: "OpenAI", Group: GroupTraining, Purpose: "Crawls pages that may be used to train OpenAI models.",
		UA: "gptbot", Token: "GPTBot", Verify: Verify{RangeSources: []string{"openai-gptbot"}}, Docs: "https://platform.openai.com/docs/bots"},
	{ID: "oai-searchbot", Name: "OAI-SearchBot", Operator: "OpenAI", Group: GroupSearch, Purpose: "Indexes pages for ChatGPT search results.",
		UA: "oai-searchbot", Token: "OAI-SearchBot", Verify: Verify{RangeSources: []string{"openai-searchbot"}}, Docs: "https://platform.openai.com/docs/bots"},
	{ID: "chatgpt-user", Name: "ChatGPT-User", Operator: "OpenAI", Group: GroupAgent, Purpose: "Fetches a page when a ChatGPT user (or a GPT action) asks for it.",
		UA: "chatgpt-user", Token: "ChatGPT-User", Verify: Verify{RangeSources: []string{"openai-chatgpt-user"}}, Docs: "https://platform.openai.com/docs/bots"},

	{ID: "claudebot", Name: "ClaudeBot", Operator: "Anthropic", Group: GroupTraining, Purpose: "Crawls pages that may be used to train Claude models.",
		UA: "claudebot", Token: "ClaudeBot", Note: anthropicNoIP, Docs: "https://support.claude.com/en/articles/8896518"},
	{ID: "claude-searchbot", Name: "Claude-SearchBot", Operator: "Anthropic", Group: GroupSearch, Purpose: "Indexes pages to improve the quality of Claude search results.",
		UA: "claude-searchbot", Token: "Claude-SearchBot", Note: anthropicNoIP, Docs: "https://support.claude.com/en/articles/8896518"},
	{ID: "claude-user", Name: "Claude-User", Operator: "Anthropic", Group: GroupAgent, Purpose: "Fetches a page when a Claude user asks for it.",
		UA: "claude-user", Token: "Claude-User", Note: anthropicNoIP, Docs: "https://support.claude.com/en/articles/8896518"},
	{ID: "anthropic-ai", Name: "anthropic-ai", Operator: "Anthropic", Group: GroupTraining, Purpose: "Older Anthropic user agent, kept so existing robots.txt files and logs still match.",
		UA: "anthropic-ai", Token: "anthropic-ai", Note: "Legacy name; current crawlers identify as ClaudeBot."},
	{ID: "claude-web", Name: "Claude-Web", Operator: "Anthropic", Group: GroupTraining, Purpose: "Older Anthropic user agent, kept so existing logs still match.",
		UA: "claude-web", Token: "Claude-Web", Note: "Legacy name; current crawlers identify as ClaudeBot."},

	{ID: "google-extended", Name: "Google-Extended", Operator: "Google", Group: GroupTraining, Purpose: "A robots.txt control token: tells Google not to use your content for Gemini training and grounding.",
		Token: "Google-Extended", TokenOnly: true, Note: "Token only: no request ever carries this name (Google's normal crawlers fetch the pages), so it works through robots.txt only and nothing can be enforced here. Googlebot is NOT an AI crawler: blocking it removes the site from Google Search.",
		Docs: "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers"},
	{ID: "gemini-deep-research", Name: "Gemini-Deep-Research", Operator: "Google", Group: GroupAgent, Purpose: "Fetches pages for a Gemini Deep Research task a person started.",
		UA: "gemini-deep-research", Token: "Gemini-Deep-Research", Note: "No verification method is documented here; Google lists its user-triggered fetchers separately.",
		Docs: "https://developers.google.com/search/docs/crawling-indexing/google-user-triggered-fetchers"},

	{ID: "perplexitybot", Name: "PerplexityBot", Operator: "Perplexity", Group: GroupSearch, Purpose: "Indexes pages for Perplexity search results.",
		UA: "perplexitybot", Token: "PerplexityBot", Verify: Verify{RangeSources: []string{"perplexity-bot"}}, Docs: "https://docs.perplexity.ai/guides/bots"},
	{ID: "perplexity-user", Name: "Perplexity-User", Operator: "Perplexity", Group: GroupAgent, Purpose: "Fetches a page when a Perplexity user asks for it.",
		UA: "perplexity-user", Token: "Perplexity-User", Verify: Verify{RangeSources: []string{"perplexity-user"}}, Note: "Perplexity states that this agent generally ignores robots.txt, because a person asked for the page.", Docs: "https://docs.perplexity.ai/guides/bots"},

	{ID: "meta-externalagent", Name: "Meta-ExternalAgent", Operator: "Meta", Group: GroupTraining, Purpose: "Crawls pages to train Meta's AI models and to index content directly.",
		UA: "meta-externalagent", Token: "meta-externalagent", Docs: "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers"},
	{ID: "meta-externalfetcher", Name: "Meta-ExternalFetcher", Operator: "Meta", Group: GroupAgent, Purpose: "Fetches a link on behalf of a person using a Meta AI product.",
		UA: "meta-externalfetcher", Token: "meta-externalfetcher", Note: "Meta documents that this fetcher may bypass robots.txt.", Docs: "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers"},
	{ID: "facebookbot", Name: "FacebookBot", Operator: "Meta", Group: GroupTraining, Purpose: "Crawls public pages to improve Meta's speech recognition and AI models.",
		UA: "facebookbot", Token: "FacebookBot", Note: "Not the link preview fetcher (facebookexternalhit), which is not in this registry.", Docs: "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers"},

	{ID: "applebot-extended", Name: "Applebot-Extended", Operator: "Apple", Group: GroupTraining, Purpose: "A robots.txt control token: tells Apple not to use your content to train its foundation models.",
		Token: "Applebot-Extended", TokenOnly: true, Note: "Token only: Applebot itself still crawls for Siri and Spotlight and is not blocked by this entry. Works through robots.txt only.",
		Docs: "https://support.apple.com/en-us/119829"},

	{ID: "bytespider", Name: "Bytespider", Operator: "ByteDance", Group: GroupTraining, Purpose: "Crawls pages for ByteDance's AI models.",
		UA: "bytespider", Token: "Bytespider", Note: "Widely reported to ignore robots.txt; block or challenge it to be sure."},
	{ID: "ccbot", Name: "CCBot", Operator: "Common Crawl", Group: GroupTraining, Purpose: "Builds the public Common Crawl archive that many models are trained on.",
		UA: "ccbot", Token: "CCBot", Verify: Verify{RangeSources: []string{"commoncrawl-ccbot"}}, Docs: "https://commoncrawl.org/ccbot"},
	{ID: "amazonbot", Name: "Amazonbot", Operator: "Amazon", Group: GroupTraining, Purpose: "Crawls pages for Amazon services such as Alexa, and may be used to improve Amazon AI models.",
		UA: "amazonbot", Token: "Amazonbot", Verify: Verify{RangeSources: []string{"amazonbot"}, RDNSSuffixes: []string{".amazonbot.amazon"}}, Docs: "https://developer.amazon.com/amazonbot"},
	{ID: "cohere-ai", Name: "cohere-ai", Operator: "Cohere", Group: GroupTraining, Purpose: "Cohere's crawler for its language models.",
		UA: "cohere-ai", Token: "cohere-ai", Note: "Cohere does not document a verification method."},
	{ID: "diffbot", Name: "Diffbot", Operator: "Diffbot", Group: GroupTraining, Purpose: "Extracts page content into a commercial knowledge graph used for AI products.",
		UA: "diffbot", Token: "Diffbot", Docs: "https://docs.diffbot.com/docs/getting-started-with-crawlbot"},
	{ID: "omgilibot", Name: "Omgilibot", Operator: "Webz.io", Group: GroupTraining, Purpose: "Collects pages for datasets that Webz.io sells, including to AI developers.",
		UA: "omgilibot", Token: "omgilibot"},
	{ID: "imagesiftbot", Name: "ImagesiftBot", Operator: "Hive", Group: GroupTraining, Purpose: "Collects images for Hive's ImageSift product and AI training sets.",
		UA: "imagesiftbot", Token: "ImagesiftBot"},

	{ID: "duckassistbot", Name: "DuckAssistBot", Operator: "DuckDuckGo", Group: GroupAgent, Purpose: "Fetches pages to produce AI-assisted answers in DuckDuckGo.",
		UA: "duckassistbot", Token: "DuckAssistBot", Note: "DuckDuckGo lists its addresses on a web page, not as a data file, so Zoraxy cannot verify it.", Docs: "https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot"},
	{ID: "mistralai-user", Name: "MistralAI-User", Operator: "Mistral", Group: GroupAgent, Purpose: "Fetches a page when a Le Chat user asks for it.",
		UA: "mistralai-user", Token: "MistralAI-User"},
	{ID: "youbot", Name: "YouBot", Operator: "You.com", Group: GroupSearch, Purpose: "Indexes pages for You.com search.",
		UA: "youbot", Token: "YouBot"},
	{ID: "timpibot", Name: "Timpibot", Operator: "Timpi", Group: GroupSearch, Purpose: "Builds the index of the Timpi decentralised search engine.",
		UA: "timpibot", Token: "Timpibot"},
}

// matchOrder: longest User-Agent token first, so a name that contains another one wins
var matchOrder = func() []int {
	idx := make([]int, 0, len(registry))
	for i, e := range registry {
		if e.UA != "" {
			idx = append(idx, i)
		}
	}
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0 && len(registry[idx[j]].UA) > len(registry[idx[j-1]].UA); j-- {
			idx[j], idx[j-1] = idx[j-1], idx[j]
		}
	}
	return idx
}()

const maxUA = 512 // longer User-Agent headers are truncated before matching

// Match returns the crawler a User-Agent claims to be (case-insensitive substring of the product token).
// Token-only entries never match. ok is false for every other client.
func Match(ua string) (Entry, bool) {
	if ua == "" {
		return Entry{}, false
	}
	if len(ua) > maxUA {
		ua = ua[:maxUA]
	}
	lower := strings.ToLower(ua)
	for _, i := range matchOrder {
		if strings.Contains(lower, registry[i].UA) {
			return registry[i], true
		}
	}
	return Entry{}, false
}
