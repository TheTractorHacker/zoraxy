# Third-party notices

Zoraxy is licensed under the GNU AGPL v3 (see [LICENSE](LICENSE)). This file lists third-party components
that are compiled into the Zoraxy binary or shipped in this repository because of the Web Application Firewall
feature. Their licences are compatible with the AGPL v3 and are reproduced in
[third_party/licenses/](third_party/licenses/). Other Go module dependencies are listed in `src/go.mod`; the
bundled sub-licences of the proxy core are listed in [DEVELOPMENT.md](DEVELOPMENT.md).

## Web Application Firewall

| Component | Version | Licence | Copyright | Licence text |
|---|---|---|---|---|
| [Coraza WAF](https://github.com/corazawaf/coraza) (`github.com/corazawaf/coraza/v3`) | v3.8.1 | Apache-2.0 | Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors | [coraza-APACHE-2.0.txt](third_party/licenses/coraza-APACHE-2.0.txt) |
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) v4.25.0, embedded unmodified through [`github.com/corazawaf/coraza-coreruleset/v4`](https://github.com/corazawaf/coraza-coreruleset) | v4.25.0 | Apache-2.0 | Copyright OWASP CRS project and contributors | [owasp-coreruleset-APACHE-2.0.txt](third_party/licenses/owasp-coreruleset-APACHE-2.0.txt) |
| [libinjection-go](https://github.com/corazawaf/libinjection-go) | v0.3.3 | BSD-3-Clause | Copyright (c) 2022-Present, Coraza | [libinjection-go-BSD-3-Clause.txt](third_party/licenses/libinjection-go-BSD-3-Clause.txt) |
| Transitive Go modules of Coraza: `petar-dambovaliev/aho-corasick`, `tidwall/gjson`, `tidwall/match`, `tidwall/pretty`, `goccy/go-json`, `goccy/go-yaml`, `kaptinlin/go-i18n`, `kaptinlin/jsonschema`, `gotnospirit/messageformat`, `gotnospirit/makeplural`, `valllabh/ocsf-schema-golang` | see `src/go.mod` | MIT, BSD-2-Clause, Apache-2.0 | see texts | [other-go-dependencies.txt](third_party/licenses/other-go-dependencies.txt) |

Notes required by the Apache License 2.0 section 4:

- The OWASP Core Rule Set files are redistributed **without modification** inside the Go module
  `github.com/corazawaf/coraza-coreruleset/v4`, which is embedded into the Zoraxy binary at build time. Zoraxy does
  not change the rule files; tuning is done through generated configuration directives (paranoia level, thresholds,
  exclusions) that are passed to the engine at runtime.
- Coraza and the Core Rule Set do not ship a `NOTICE` file at the pinned versions.
- Zoraxy's own source files are not derived from Coraza or CRS source code; they use the public Coraza Go API.

## Authentik / OIDC support

- **github.com/go-jose/go-jose/v4** - Apache-2.0. JWT/JWS parsing and signature verification of OIDC ID tokens
  (`src/mod/auth/sso/oauth2`). Already a transitive dependency; now a direct one.
- **golang.org/x/oauth2** - BSD-3-Clause. OAuth 2.0 authorization code flow, PKCE helpers and token refresh.
- **github.com/jellydator/ttlcache/v3** - MIT. Expiring in-memory session and login-state stores.

## Advanced redirect regex

- **github.com/dlclark/regexp2** v1.12.0 - MIT (licence text: its `LICENSE`). A .NET-style backtracking regular expression engine with
  lookahead, lookbehind and backreferences, used only when an admin enables the "advanced regex" mode of the redirect rules
  (`src/mod/dynamicproxy/redirection/advanced.go`). Every match runs under a hard timeout; MIT is compatible with AGPL-3.0.

## Lua script handlers

- **github.com/yuin/gopher-lua** v1.1.2 - MIT, Copyright (c) 2015 Yusuke Inuzuka. Lua 5.1 virtual machine used by the per-rule script
  handler / hook (`src/mod/luascript`). Licence text: [gopher-lua-MIT.txt](third_party/licenses/gopher-lua-MIT.txt). The Lua pattern
  matcher in `src/mod/luascript/lpattern.go` is an original Go port of the algorithm in the Lua 5.1 reference implementation
  (`lstrlib.c`, MIT, Copyright (C) 1994-2012 Lua.org, PUC-Rio) with a step budget added.
