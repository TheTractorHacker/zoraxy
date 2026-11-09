package waf

import (
	"bytes"
	"hash/crc32"
	"math"
	"regexp"
	"strings"
)

/*
	respsignatures.go

	Built-in signatures of response inspection. Every signature belongs to one
	group, has a stable ID and a one line description (Doc) that is also shown in
	the reference table of DEVELOPMENT.md.

	Design rules, to keep the false positive rate low:
	  - patterns are anchored on structure that ordinary prose does not have
	    (several consecutive stack frames, a message together with its error code
	    or driver class, a header line with a base64 body behind it, ...)
	  - token formats that have a checksum are verified; a token with a bad
	    checksum is only reported with low confidence
	  - every signature has a confidence. Only high confidence hits are eligible
	    for the "block" action, low confidence hits (an AWS key ID alone, a Stripe
	    test key, a JSON "password" value) are logged at most
	  - every regex is guarded by a cheap literal prefilter (bytes.Contains), so
	    the regex engine only runs on pages that could possibly match
*/

const (
	confNone = 0
	confLow  = 1 // logged, never blocks
	confHigh = 2 // eligible for block
)

// Content flags a signature may require
const (
	ctxJSON  = 1 << iota // body is JSON
	ctxPlain             // body is text/plain
)

type signature struct {
	ID    string
	Group string
	Name  string
	Doc   string

	pre    [][]byte // anchors: literals of which at least one is part of every match; the regex only runs around them
	preIDs []int
	re     *regexp.Regexp
	need   int                                 // content flags, any of them must be present (0 = any content)
	check  func(data []byte, loc []int) int    // confidence of a regex hit; nil = confHigh
	value  int                                 // secrets: index of the sub-match holding the secret to mask (0 = whole match)
	keep   int                                 // secrets: characters of the secret that stay visible at the start (-1 = none)
	plain  func(data []byte, loc []int) string // optional custom redacted sample
}

func lits(s ...string) [][]byte {
	out := make([][]byte, len(s))
	for i, v := range s {
		out[i] = []byte(strings.ToLower(v)) // the anchor matcher is case insensitive (ASCII)
	}
	return out
}

func rx(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

// sep between lines of a trace that may be rendered as HTML
const htmlNL = `(?:\s|<br\s*/?>|&nbsp;|</?(?:li|div|span|pre|p|code|b)[^>]*>)*`

// builtinSignatures is the complete signature list, in report order
var builtinSignatures = []*signature{
	/* ---- stack traces and debug pages ---- */
	{ID: "ST-JAVA", Group: GroupStackTrace, Name: "Java / JVM stack trace",
		Doc: "Three or more consecutive 'at pkg.Class.method(File.java:12)' frames (also Kotlin, Scala, Groovy, Native Method, Unknown Source).",
		pre: lits(".java:", ".kt:", ".scala:", ".groovy:", "(native method)", "(unknown source)"),
		re:  rx(`(?:\bat [\w$.<>/]+\((?:[\w$]+\.(?:java|kt|scala|groovy):\d+|Native Method|Unknown Source)\)` + htmlNL + `){3}`)},
	{ID: "ST-PY", Group: GroupStackTrace, Name: "Python traceback",
		Doc: "'Traceback (most recent call last):' directly followed by a 'File \"...\", line N' frame.",
		pre: lits("traceback (most recent call last)"),
		re:  rx(`Traceback \(most recent call last\):` + htmlNL + `File (?:"|&quot;)[^"\n<&]{1,200}(?:"|&quot;), line \d+`)},
	{ID: "ST-PHP", Group: GroupStackTrace, Name: "PHP error message with file path",
		Doc: "'Fatal error / Parse error / Warning / Notice / Deprecated: message in /path/file.php on line N' (plain or HTML form).",
		pre: lits("fatal error:", "fatal error</b>:", "parse error:", "parse error</b>:", "warning:", "warning</b>:", "notice:", "notice</b>:", "deprecated:", "deprecated</b>:"),
		re:  rx(`\b(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:\s+[^\n]{1,300}? in (?:<b>)?(?:/|[A-Za-z]:\\)[^\n<>]{1,200}?\.(?:php|phtml|inc)(?:</b>)?(?: on line |:)(?:<b>)?\d+`)},
	{ID: "ST-PHP-TRACE", Group: GroupStackTrace, Name: "PHP stack trace",
		Doc: "'Stack trace:' followed by '#0 /path/file.php(N)'.",
		pre: lits("stack trace:"),
		re:  rx(`Stack trace:` + htmlNL + `#0 [^\n]{1,200}?\.php\(\d+\)`)},
	{ID: "ST-DOTNET-PAGE", Group: GroupStackTrace, Name: "ASP.NET error page",
		Doc: "The yellow 'Server Error in '/' Application' page including its 'Stack Trace:' or 'Exception Details:' section.",
		pre: lits("server error in '"),
		re:  rx(`Server Error in '[^']{1,100}' Application`),
		check: func(d []byte, l []int) int {
			rest := d[l[1]:]
			if bytes.Contains(rest, []byte("Stack Trace:")) || bytes.Contains(rest, []byte("Exception Details:")) {
				return confHigh
			}
			return confNone
		}},
	{ID: "ST-DOTNET", Group: GroupStackTrace, Name: ".NET stack trace",
		Doc: "Two or more '   at Namespace.Class.Method(args) in File.cs:line N' frames (needs a PDB).",
		pre: lits(":line "),
		re:  rx(`(?:\bat [\w.<>` + "`" + `$+\[\]]+\([^)\n]{0,200}\) in [^\n<]{1,260}:line \d+` + htmlNL + `){2}`)},
	{ID: "ST-NODE", Group: GroupStackTrace, Name: "Node.js stack trace",
		Doc: "Three or more consecutive '    at fn (/path/file.js:line:col)' frames with absolute paths, file:// or node: URLs.",
		pre: lits(".js:", ".mjs:", ".cjs:", ".ts:", ".tsx:", "node:internal"),
		re:  rx(`(?:(?:\s|<br\s*/?>|&nbsp;)+at (?:[^\n(]{1,120} \()?(?:/|[A-Za-z]:\\|file:///|node:)[^\n):<]{1,300}:\d+:\d+\)?){3}`)},
	{ID: "ST-GO", Group: GroupStackTrace, Name: "Go panic / goroutine dump",
		Doc: "'goroutine N [state]:' followed by a function line and a 'file.go:N' line.",
		pre: lits("goroutine "),
		re:  rx(`goroutine \d+ \[[a-z ]{3,25}(?:, \d+ minutes)?\]:\r?\n[^\n]{1,300}\r?\n\s+[^\n]{1,300}\.go:\d+`)},
	{ID: "ST-RAILS", Group: GroupStackTrace, Name: "Rails debug page",
		Doc: "'Action Controller: Exception caught' page title or a 'Rails.root: /path' line.",
		pre: lits("action controller: exception caught", "rails.root:"),
		re:  rx(`<title>Action Controller: Exception caught</title>|Rails\.root: /[^<\n]{1,200}`)},
	{ID: "ST-DJANGO", Group: GroupStackTrace, Name: "Django debug page",
		Doc: "The 'You're seeing this error because you have DEBUG = True' notice, or the Django Version / Exception Type table.",
		pre: lits("debug = true", "django version:"),
		re:  rx(`(?s)You're seeing this error because you have <code>DEBUG = True</code>|Django Version:.{0,400}?Exception Type:`)},
	{ID: "ST-WERKZEUG", Group: GroupStackTrace, Name: "Flask / Werkzeug debugger",
		Doc: "'The debugger caught an exception in your WSGI application'.",
		pre: lits("the debugger caught an exception"),
		re:  rx(`The debugger caught an exception in your WSGI application`)},

	/* ---- database errors ---- */
	{ID: "DB-MYSQL", Group: GroupDBError, Name: "MySQL / MariaDB error",
		Doc: "'You have an error in your SQL syntax ... MySQL/MariaDB server version', PDO 'SQLSTATE[..]: ..: 1064 ..', 'Unknown column ... in field list', 'Duplicate entry ... for key', Connector/J exception classes, mysql_*() warnings.",
		pre: lits("sql syntax", "sqlstate[", "unknown column '", "' doesn't exist", "duplicate entry '", "com.mysql.", "() expects parameter", "not a valid mysql"),
		re: rx(`You have an error in your SQL syntax; check the manual that corresponds to your (?:MySQL|MariaDB) server version` +
			`|SQLSTATE\[[0-9A-Z]{5}\]: [^:\n]{1,100}: \d{3,5} [^\n]{1,200}` +
			`|Unknown column '[^'\n]{1,100}' in '(?:field list|where clause|order clause|on clause|having clause|group statement)'` +
			`|Table '[\w$\-]{1,64}\.[\w$\-]{1,64}' doesn't exist` +
			`|Duplicate entry '[^'\n]{0,200}' for key '` +
			`|com\.mysql\.(?:cj\.)?jdbc\.exceptions\.\w+` +
			`|mysqli?_\w+\(\) expects parameter|supplied argument is not a valid MySQL`)},
	{ID: "DB-PGSQL", Group: GroupDBError, Name: "PostgreSQL error",
		Doc: "'ERROR:  syntax error at or near', 'relation \"x\" does not exist', 'duplicate key value violates unique constraint', PSQLException, PG::Error, psycopg2 errors, pg_query() failures.",
		pre: lits("syntax error at or near", "\" does not exist", "invalid input syntax for", "duplicate key value violates", "unterminated quoted string", "psqlexception", "pg::", "pg_query()", "psycopg"),
		re: rx(`ERROR:\s+(?:syntax error at or near "[^"\n]{0,50}"|relation "[^"\n]{1,100}" does not exist|column "[^"\n]{1,100}" (?:of relation "[^"\n]+" )?does not exist|invalid input syntax for (?:type )?[a-z ]{3,30}: |duplicate key value violates unique constraint "|unterminated quoted string at or near)` +
			`|org\.postgresql\.util\.PSQLException|\bPG::[A-Z]\w+Error|pg_query\(\): Query failed|psycopg2?\.(?:errors\.)?\w*Error`)},
	{ID: "DB-MSSQL", Group: GroupDBError, Name: "Microsoft SQL Server error",
		Doc: "'Unclosed quotation mark after the character string', 'Incorrect syntax near', ODBC / OLE DB provider names, SqlException classes, 'Msg N, Level N, State N'.",
		pre: lits("unclosed quotation mark", "incorrect syntax near", "[microsoft][odbc", "sqlexception", "ole db provider for sql", ", level ", "conversion failed when"),
		re: rx(`Unclosed quotation mark after the character string '|Incorrect syntax near (?:the keyword )?'[^'\n]{0,50}'` +
			`|\[Microsoft\]\[ODBC SQL Server Driver\]|(?:System|Microsoft)\.Data\.SqlClient\.SqlException|Microsoft OLE DB Provider for SQL Server` +
			`|\bMsg \d{3,5}, Level \d{1,2}, State \d{1,2}|Conversion failed when converting (?:the \w+ value|date and/or time)`)},
	{ID: "DB-ORACLE", Group: GroupDBError, Name: "Oracle error",
		Doc: "'ORA-NNNNN: message' (colon and message required, a bare error code in prose does not match), PLS-NNNNN, Oracle JDBC exception classes.",
		pre: lits("ora-0", "ora-1", "ora-2", "ora-3", "ora-4", "ora-5", "ora-6", "ora-7", "ora-8", "ora-9", "pls-0", "pls-1", "pls-2", "oracle.jdbc"),
		re:  rx(`\bORA-\d{5}: [A-Za-z]|\bPLS-\d{5}: [A-Za-z]|oracle\.jdbc\.(?:driver\.)?Oracle\w*Exception`)},
	{ID: "DB-SQLITE", Group: GroupDBError, Name: "SQLite error",
		Doc: "SQLite3::SQLException, sqlite3.OperationalError, 'SQLITE_ERROR: ', 'near \"x\": syntax error', System.Data.SQLite.SQLiteException.",
		pre: lits("sqlite3::", "sqlite3.", "sqlite_error", "sqlite_constraint", "sqlite_misuse", "sqlite_cantopen", "\": syntax error", "sqliteexception", "unrecognized token: \""),
		re: rx(`SQLite3::\w*Exception|\bsqlite3\.(?:Operational|Integrity|Programming|Database)Error|\bSQLITE_(?:ERROR|CONSTRAINT|MISUSE|CANTOPEN): ` +
			`|near "[^"\n]{1,50}": syntax error|System\.Data\.SQLite\.SQLiteException|unrecognized token: "`)},
	{ID: "DB-MONGO", Group: GroupDBError, Name: "MongoDB error",
		Doc: "'MongoServerError: ' / 'MongoError: ', com.mongodb exceptions, 'E11000 duplicate key error', PHP driver and pymongo exception classes, mongoose CastError.",
		pre: lits("mongoerror: ", "mongoserver", "mongonetwork", "mongowrite", "mongoparse", "mongobulk", "com.mongodb.", "e11000 duplicate", "mongodb\\driver", "pymongo.errors", "cast to objectid"),
		re: rx(`\bMongo(?:Server|Network|Write|Parse|Bulk\w*|ServerSelection)?Error: [^\n]{1,200}|com\.mongodb\.Mongo\w*Exception|E11000 duplicate key error (?:collection|index)` +
			`|MongoDB\\Driver\\Exception\\|pymongo\.errors\.\w+|Cast to ObjectId failed for value`)},

	/* ---- secrets ---- */
	{ID: "SEC-PEM", Group: GroupSecrets, Name: "Private key (PEM)",
		Doc:   "'-----BEGIN [RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP] PRIVATE KEY-----' followed by at least 40 base64 characters (an elided '...' example or a bare header does not match). Public keys and certificates are not matched.",
		pre:   lits("private key"),
		re:    rx(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\s|\\r|\\n){0,6})([A-Za-z0-9+/=]{40,})`),
		value: 2, keep: -1},
	{ID: "SEC-AWS-SECRET", Group: GroupSecrets, Name: "AWS secret access key",
		Doc: "A labelled 40 character secret: aws_secret_access_key / SecretAccessKey / secret_access_key = <40 chars base64>. The documented placeholder values (containing EXAMPLE) are ignored.",
		pre: lits("secret_access_key", "secretaccesskey", "secret_key", "secretkey"),
		re:  rx(`(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b`),
		check: func(d []byte, l []int) int {
			if !plausibleSecretValue(string(d[l[2]:l[3]])) {
				return confNone
			}
			return confHigh
		}, value: 1, keep: -1},
	{ID: "SEC-AWS-KEYID", Group: GroupSecrets, Name: "AWS access key ID",
		Doc:   "AKIA/ASIA/AGPA/AIDA/AROA/ANPA/ANVA + 16 base32 characters. Low confidence on its own (an ID is not a secret); high confidence when a 40 character secret-looking token follows or precedes within 160 bytes. AWS documentation placeholders (EXAMPLE) are ignored.",
		pre:   lits("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva"),
		re:    rx(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z2-7]{16}\b`),
		check: awsKeyIDConfidence, keep: 4},
	{ID: "SEC-GITHUB", Group: GroupSecrets, Name: "GitHub token",
		Doc:   "ghp_/gho_/ghu_/ghs_/ghr_ + 36 base62 characters whose last 6 characters are the base62 CRC32 of the first 30 (high confidence); same shape with a wrong checksum is low confidence. github_pat_ fine-grained tokens (22 + 59 characters).",
		pre:   lits("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
		re:    rx(`\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
		check: githubTokenConfidence, keep: 4},
	{ID: "SEC-GITLAB", Group: GroupSecrets, Name: "GitLab personal access token",
		Doc: "glpat- + 20 to 50 URL-safe base64 characters, with enough variety (placeholders such as glpat-xxxxxxxxxxxxxxxxxxxx do not match).",
		pre: lits("glpat-"),
		re:  rx(`\bglpat-[A-Za-z0-9_\-]{20,50}\b`),
		check: func(d []byte, l []int) int {
			if !plausibleSecretValue(string(d[l[0]+6 : l[1]])) {
				return confNone
			}
			return confHigh
		}, keep: 6},
	{ID: "SEC-SLACK", Group: GroupSecrets, Name: "Slack token / webhook",
		Doc: "xox[bpoase]-<9-13 digits>-<9-13 digits>[-<9-13 digits>]-<24-48 alphanumerics>, xapp- app tokens, hooks.slack.com/services/T../B../<24 chars> webhook URLs.",
		pre: lits("xoxb-", "xoxp-", "xoxo-", "xoxa-", "xoxs-", "xoxe-", "xapp-", "hooks.slack.com/services/"),
		re: rx(`\bxox[bpoase]-[0-9]{9,13}-[0-9]{9,13}(?:-[0-9]{9,13})?-[A-Za-z0-9]{24,48}\b` +
			`|\bxapp-\d-[A-Z0-9]{9,12}-\d{10,14}-[a-f0-9]{60,70}\b` +
			`|hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}\b`),
		keep: 4},
	{ID: "SEC-STRIPE", Group: GroupSecrets, Name: "Stripe secret key",
		Doc: "sk_live_ / rk_live_ + 24 to 99 alphanumerics (high confidence, placeholders ignored). sk_test_ / rk_test_ keys are reported with low confidence. Publishable pk_ keys are not secrets and are not matched.",
		pre: lits("sk_live_", "rk_live_", "sk_test_", "rk_test_"),
		re:  rx(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,99}\b`),
		check: func(d []byte, l []int) int {
			m := d[l[0]:l[1]]
			if !plausibleSecretValue(string(m[8:])) {
				return confNone
			}
			if bytes.Contains(m, []byte("_test_")) {
				return confLow
			}
			return confHigh
		}, keep: 8},
	{ID: "SEC-JSON-CRED", Group: GroupSecrets, Name: "Credential value in JSON",
		Doc:  "Only in JSON bodies: a key such as password, passwd, secret, api_key, access_token, client_secret, private_key with a 8-128 character string value that looks real (no whitespace, not a placeholder such as changeme / xxxx / ${VAR}, mixed character classes, some entropy). Always low confidence: it is logged but never blocks.",
		pre:  lits(`password"`, `passwd"`, `pwd"`, `secret"`, `_key"`, `apikey"`, `privatekey"`, `secretkey"`, `token"`),
		re:   rx(`(?i)"(?:password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token|client_secret|private_?key|secret_?key)"\s*:\s*"([^"\\\s]{8,128})"`),
		need: ctxJSON,
		check: func(d []byte, l []int) int {
			if !plausibleSecretValue(string(d[l[2]:l[3]])) {
				return confNone
			}
			return confLow
		}, value: 1, keep: -1},
	{ID: "SEC-DOTENV", Group: GroupSecrets, Name: "Exposed .env style secret",
		Doc:  "Only in text/plain bodies: a line start 'NAME_PASSWORD=value', 'SECRET_KEY=', 'API_KEY=', 'ACCESS_KEY=', 'PRIVATE_KEY=' with a plausible 8+ character value. Always low confidence.",
		pre:  lits("password=", "secret=", "secret_key=", "api_key=", "access_key=", "private_key=", "token="),
		re:   rx(`(?m)^(?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|SECRET|SECRET_KEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN)=([^\s"']{8,128})\r?$`),
		need: ctxPlain,
		check: func(d []byte, l []int) int {
			if !plausibleSecretValue(string(d[l[2]:l[3]])) {
				return confNone
			}
			return confLow
		}, value: 1, keep: -1},

	/* ---- directory listings ---- */
	{ID: "DL-INDEXOF", Group: GroupDirListing, Name: "Apache / nginx 'Index of' listing",
		Doc: "<title>Index of /...</title> or <h1>Index of /...</h1> together with a 'Parent Directory' link, a '../' link or the Apache sort links (?C=N;O=D).",
		pre: lits("index of /"),
		re:  rx(`(?is)<(?:title|h1)>Index of /[^<]{0,200}</(?:title|h1)>.{0,1000}?(?:Parent Directory|<a href="\.\./?">|\?C=[NMSD];O=[AD])`)},
	{ID: "DL-PYHTTP", Group: GroupDirListing, Name: "Python http.server / Go FileServer listing",
		Doc: "<title>Directory listing for /...</title> followed by a <ul> or <pre> of links.",
		pre: lits("directory listing for /"),
		re:  rx(`(?is)<title>Directory listing for /[^<]{0,200}</title>.{0,500}?<(?:ul|pre)>`)},
	{ID: "DL-IIS", Group: GroupDirListing, Name: "IIS directory listing",
		Doc: "The '[To Parent Directory]' link of the IIS listing.",
		pre: lits("[to parent directory]"),
		re:  rx(`\[To Parent Directory\]`)},
}

// ---- helpers ----

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var placeholderWords = []string{"password", "passwd", "changeme", "change_me", "example", "your", "xxxx", "****", "....", "<", ">", "{{", "}}", "${", "%s", "%(",
	"null", "undefined", "redacted", "secret", "dummy", "sample", "todo", "placeholder", "12345678", "abcdefgh", "qwerty", "none", "fake", "token", "key_here", "insert"}

// plausibleSecretValue rejects placeholders and low variety values: a documented example must not look like a leak
func plausibleSecretValue(v string) bool {
	if len(v) < 8 {
		return false
	}
	lv := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(lv, w) {
			return false
		}
	}
	var lower, upper, digit, other bool
	distinct := map[byte]bool{}
	for i := 0; i < len(v); i++ {
		c := v[i]
		distinct[c] = true
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	return classes >= 2 && len(distinct) >= 7 && shannon(v) >= 2.8
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// githubChecksum returns the 6 character base62 CRC32 that ends a GitHub token (and its first 30 random characters)
func githubChecksum(random30 string) string {
	n := crc32.ChecksumIEEE([]byte(random30))
	out := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		out[i] = base62Alphabet[n%62]
		n /= 62
	}
	return string(out)
}

func githubTokenConfidence(d []byte, l []int) int {
	m := string(d[l[0]:l[1]])
	if strings.HasPrefix(m, "github_pat_") {
		if !plausibleSecretValue(m[11:]) {
			return confNone
		}
		return confHigh
	}
	body := m[4:] // 36 characters
	if !plausibleSecretValue(body) {
		return confNone
	}
	if githubChecksum(body[:30]) == body[30:] {
		return confHigh
	}
	return confLow
}

var awsSecretShape = regexp.MustCompile(`[A-Za-z0-9/+]{40}`)

func awsKeyIDConfidence(d []byte, l []int) int {
	id := d[l[0]:l[1]]
	if bytes.Contains(id, []byte("EXAMPLE")) {
		return confNone
	}
	lo, hi := l[0]-160, l[1]+160
	if lo < 0 {
		lo = 0
	}
	if hi > len(d) {
		hi = len(d)
	}
	ctx := d[lo:hi]
	for _, loc := range awsSecretShape.FindAllIndex(ctx, 8) {
		tok := string(ctx[loc[0]:loc[1]])
		// the token must be a standalone 40 character word, not a slice of a longer blob
		if loc[0] > 0 && isB64(ctx[loc[0]-1]) || loc[1] < len(ctx) && isB64(ctx[loc[1]]) {
			continue
		}
		if bytes.Contains([]byte(tok), id) || strings.Contains(strings.ToUpper(tok), "EXAMPLE") {
			continue
		}
		hasDigit := strings.ContainsAny(tok, "0123456789")
		hasLower := strings.ToUpper(tok) != tok
		hasUpper := strings.ToLower(tok) != tok
		if hasDigit && hasLower && hasUpper && shannon(tok) >= 4.0 {
			return confHigh
		}
	}
	return confLow
}

func isB64(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '+'
}
