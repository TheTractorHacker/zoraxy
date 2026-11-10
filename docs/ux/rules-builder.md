# Security rules: the visual rules builder

Phase 5 of the redesign in [audit-2026-11.md](audit-2026-11.md). Menu: **Security > Rules** (`#ruleset`), palette: "Create a security rule", "Test a request against the rules" and more. It is a front end for the rules engine API (`/api/ruleset/*`, see "Rules engine" in `DEVELOPMENT.md`); nothing here adds engine behaviour.

| Part | File |
|---|---|
| Page markup and layout CSS | `src/web/components/ruleset.html` |
| List, lists, import, request tester, enforce dialog | `src/web/script/rulesbuilder.js` |
| Visual editor (conditions, action, mode, text view, save) | `src/web/script/rulesedit.js` |
| Model (tree <-> builder, plain-English sentence); no DOM | `src/web/script/rulesmodel.js` |
| Data: field groups and labels, operator wording, action labels, countries, quick-start templates | `src/web/script/rulesdata.js` |

## Using it

1. **Rules** tab: pick the scope (all sites, the default site, or one proxy rule), see the rules in evaluation order. Each row has the plain-English sentence, action and mode badges, match counts (total, while log-only, a 24 h sparkline) and last match, an enable switch (applies at once, toast says so), move up / down, edit, duplicate (the copy is disabled and log-only), delete (confirmation, Undo in the toast). Click the mode badge to switch between **Log-only** and **Enforcing**. Long lists render 100 rows at a time ("Show more") and can be searched.
2. **New rule** or a **template** (block a country, allow only my IP to /admin, block bad user agents, rate limit a login path, redirect an old path, require a challenge for a path, add a security header). Templates are data in `rulesdata.js` (`RBData.templates`) and always open the builder **log-only** with the empty parts for you to fill in.
3. In the builder: condition rows (field grouped as Request / Headers and cookies / Client / TLS, an operator that fits the field, a value widget that fits the field and operator), AND / OR groups that nest, NOT on a condition or a group, "Ignore case". The sentence at the top ("When the path starts with /admin and the country is not US, block with status 403.") and the canonical expression (read only, Copy) update as you type; the server validates every change (`/api/ruleset/validate`) and shows errors under the condition they belong to, plus the engine's warnings before you save.
4. **Edit as text (advanced)** shows the expression in a text area, re-parsed on every change with the error line and column marked. Switching back needs a valid text and restores the same tree (text -> tree -> text is lossless; the engine normalises spacing and a single-child group).
5. **Then**: the action and its parameters (block status and message, redirect status and URL template with insert buttons, challenge TTL, rate limit rate / burst / status, skip targets, header actions, tag). "Report to the automatic ban" is off by default and explained.
6. **Mode**: Log-only (default) or Enforce; the **enabled** switch. Saving is explicit with the kit save bar ("Create rule" / "Save rule", Ctrl+S). Going from log-only to enforce (or saving an enforcing rule that can lock you out) opens **Enforce this rule?** with the tester for a sample request and the lock-out warning.
7. **Test this rule**: URL, method, client IP, country, headers; `/api/ruleset/test` runs the **draft** and reports whether it matches, with the truth value of every condition. "Test this rule against..." jumps there. The **Request tester** tab does the same for all saved rules of a scope: matched rules in order, the first terminating decision, tags, skips, header changes, and the sentence "nothing was performed".
8. **Lists**: named IP / country / text lists with the limits shown, "used by N rules", a delete that is refused while a rule uses the list (the API refuses as well). **Import**: reads `/api/ruleset/migrate`, shows each proposal with exact / approximate and the notes, lets you pick, creates lists first and then the rules as log-only; "What cannot be converted" is listed.

### Lock-out warning

Shown in the editor and again in the enforce dialog for rules that block, challenge, redirect or rate limit. Client side: the rule set belongs to the host you use for the admin UI, a condition names that host, a pattern that matches every path, or only negative conditions on country / client address ("blocks everybody who is not on the list"). Server side (three calls to the tester with the draft): does it match a request to the admin address from a public client, an unrelated host, a private (LAN) client. Honest limit: Zoraxy's admin listener is not served through the proxy rules, so this only matters when a proxy rule fronts the admin UI; the checks are heuristics, not a proof.

## AI proposals

`aiassist.ValidateProposal` is set in `src/aiassist_rules.go` to the rules engine's validator, so a proposal with an invented field, a bad regex or a missing list is rejected before it is shown, and the model is told the real grammar. On the AI page each proposal has **Add as log-only rule** (confirmation dialog showing the rule, scope and the action's parameters; `rate_limit` uses a fixed 10 req/s, burst 20 that you change in the builder) and **Open in builder**. Both are explicit clicks; the rule is created through `/api/ruleset/rule/create` with `dry_run: true`, and nothing is ever enforced automatically. The engine has one action per rule (no separate tag), so the origin is marked by the description prefix `[AI proposal] `, shown as a badge in the list and a notice in the editor.

## Keyboard model

* Everything is a native button, select, input, textarea or checkbox: Tab / Shift+Tab in reading order, Space / Enter activate. The tabs of the page follow the kit (Left / Right / Home / End).
* A condition row is `role=group` "Condition N of M"; a group header is `role=group` "Condition group". Buttons on rows and groups: move up, move down, put in its own group (rows), ungroup (groups), remove. **Alt+Up / Alt+Down** in a text field of a row move the row (not from a dropdown, where the browser uses that key).
* After a structural change the focus goes back to the button used (or to the new row's field); moves are announced in a live region ("Moved to position 2 of 3").
* Country picker: type a name or code, **Enter** adds it, each chosen country is a button that removes it.
* Dialogs trap Tab, close with Escape and return the focus. Rule list rows have move buttons instead of drag and drop (drag was not built because a pointer-only interaction would need a full keyboard alternative anyway).
* Inline errors are linked to their control (`aria-invalid`); the sentence is a polite live region.

## Security notes

Rule names, descriptions, values, list entries, tester output and AI text are inserted with `textContent` only (the `h()` helper never takes HTML). The smoke test creates a rule and a list full of markup and checks that no element or script appears.

## Verified / not verified

Verified by `tools/ui-smoke` (`--rules-only`): building a rule through the UI (rows, nested group, country picker, header with key), text view round trip and error display, save as log-only, tester inside the editor, list actions, enable / disable, reorder, enforce dialog (cancel and confirm), lock-out warning, delete, list CRUD and the refused delete, import (migrate response mocked, creation real), hostile content, the AI proposal path against a mock provider, 500 rules in one scope with paging and search, light / dark / 390 px screenshots without horizontal overflow. **Not verified:** real screen readers, touch devices, browsers other than Chromium, a live migrate with real path / bot rules in the browser (covered by the Go tests of the endpoint), drag and drop (not built).
