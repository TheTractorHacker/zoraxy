# Translating the Zoraxy admin UI

The admin UI is plain HTML and jQuery with English text written directly in the pages, and there is no build step.
Translation therefore happens **at runtime in the browser**: `src/web/script/i18n.js` looks every piece of visible
text up in a dictionary (`src/web/locales/<code>.json`) whose keys are the **exact English text**. You never edit the
HTML to translate it.

Shipped languages: `zh-CN` (Simplified Chinese, the most complete), `zh-TW`, `es`, `de`, `fr`, `ja`, `pt-BR`, `ru`.
All of them are machine-assisted and marked `"reviewed": false` in their `_meta` block. Native-speaker review is the most
valuable contribution you can make.

## How the dictionary works

```json
{
  "_meta": { "language": "German", "reviewed": false, "author": "machine-assisted (Claude)", "coverage": 27.1 },
  "strings": {
    "Save": "Speichern",
    "Deleted {0} rules": "{0} Regeln gelöscht"
  },
  "rules": [
    { "re": "^Base version (\\S+) \\(build date unknown\\)$", "to": "Basisversion $1 (Build-Datum unbekannt)" }
  ]
}
```

* **Keys** are the English text, trimmed with runs of whitespace collapsed to one space. Markup is not part of the key:
  `<b>Hello</b> world` is two text nodes, `Hello` and `world`.
* **`{0}`, `{1}`, ...** stand for dynamic parts. A key with placeholders is also a *pattern*: `"Deleted {0} rules"` matches the
  rendered text `Deleted 5 rules` and the translation gets the captured value. Every placeholder of the key must appear in the
  translation (the check enforces it); you may reorder them.
* **`rules`** are regular expressions (`re`, JavaScript syntax) with `$1`-style groups, for sentences the extractor cannot
  turn into keys. Prefer `strings` whenever possible.
* Missing keys silently stay English. A partial translation is fine.
* Do not translate product and protocol names (Zoraxy, ACME, TLS, OIDC, HTTP, CAPTCHA, ...). Follow
  `src/web/locales/GLOSSARY.md` so the same term is used everywhere.
* Machine-readable text that must stay English (identifiers, config keys, code samples) can be excluded with the attribute
  `data-i18n-skip` on the element. `code`, `pre`, `textarea`, `script` and `style` content is never translated.

## Improve or add a language

1. Pick the code (`ll` or `ll-CC`, e.g. `it`, `ko`, `nl`). Copy a small locale file, or let the tool start one:
   `python3 tools/i18n/extract.py --missing de > /tmp/todo.txt` lists what is not yet translated (add `--core` for the main screens only).
2. Edit `src/web/locales/<code>.json`. Keep the file sorted and valid JSON (UTF-8, no BOM).
3. New language: add it to `LANGS` in `src/web/script/i18n.js`, to `Supported` in `src/mod/i18n/i18n.go` and (for the visitor-facing
   pages) add a table to `src/mod/i18n/pagetext.go`. Also add a column to `GLOSSARY.md`.
4. Run the tools (below), open the UI in your language and click through it.
5. Set `"reviewed": true` and put your name in `author` only if a native speaker looked at the whole file.

## Tools

```sh
python3 tools/i18n/extract.py            # rescans src/web/** and rewrites locales/en.json, prints coverage per locale
python3 tools/i18n/extract.py --check    # CI: en.json current, no stale keys, placeholder parity, valid rules, _meta present
python3 tools/i18n/extract.py --missing zh-CN --core   # what is left to translate on the main screens
python3 tools/i18n/extract.py --write-meta             # store coverage numbers in each locale's _meta
python3 tools/i18n/merge.py de part1.json part2.json   # merge flat {"English": "translation"} files into locales/de.json
```

Strings that only exist at runtime (built in JavaScript) are found by the coverage scan, which opens every page with a locale
enabled and prints the visible text that is still English (needs Playwright, see `DEVELOPMENT.md`):

```sh
PY=$HOME/ui-test-tools/py.sh   # any python with playwright + chromium
# start a throw-away instance, e.g. with tools/ui-smoke/run.sh, then:
$PY tools/i18n/scan.py --url http://127.0.0.1:28801 --lang de [--snippets] [--emit-extra extra.txt]
```

Add runtime-only strings that are worth translating to `tools/i18n/extra_keys.txt` (use `{0}` for dynamic parts), re-run
`extract.py`, then translate them.

## In code

* New static text: just write English in the HTML; extract + translate.
* Text assembled in JavaScript: write complete sentences with placeholders so translators can reorder:
  `tf("Deleted {0} rules", n)` (or keep the old concatenation and add a `rules` entry). `t("English")` translates one string.
  `msgbox`, `confirmBox`, `alert` and everything inserted into the DOM are translated automatically.
* Never compare or store UI text read back from the DOM (it may be translated). `i18n.originalText(el)` returns the English text.
* Server rendered visitor pages (CAPTCHA challenge / failed / blocked, built-in 403 / 404 / 521) use `Accept-Language`
  negotiation and the Go tables in `src/mod/i18n`; custom branding text and operator templates always win and are never translated.

## Layout

Translations are often longer (German, Russian) or need CJK fonts. `tools/ui-audit/audit.py --lang de` and
`tools/ui-smoke/smoke.py` (the i18n scenario) screenshot the UI per language; look for clipped buttons, table headers and menus.
