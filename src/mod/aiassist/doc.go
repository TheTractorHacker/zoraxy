// Package aiassist is the optional AI assistant.
//
// It is OFF by default, bring-your-own-key (or a local model) and it only PROPOSES: every
// model output is untrusted data that is schema-validated and allow-listed, nothing is
// applied by this package, and a human applies each change through the existing validated
// admin APIs. See the "AI assistant" section of DEVELOPMENT.md for the design, the data
// policy, the threat model and the budget semantics.
//
// Layout:
//
//	secret.go    per-install key file, AES-256-GCM sealed API key, IP pseudonyms
//	settings.go  settings (conf/aiassist/settings.json), validation, public view
//	ssrf.go      endpoint validation and the guarded HTTP client
//	redact.go    the ONE place every outbound payload passes through
//	provider.go  Anthropic Messages and OpenAI-compatible clients (plain net/http)
//	limits.go    monthly token budget, per-minute rate limit, concurrency
//	schema.go    strict validation of model output
//	features.go  explain / suggest / rule / audit
//	http.go      /api/ai/* handlers
package aiassist
