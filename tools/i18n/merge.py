#!/usr/bin/env python3
"""Merge partial translation files into src/web/locales/<code>.json.

  merge.py zh-CN part1.json part2.json ...

Each part is a flat {"English": "translation"} object.  Entries whose key is not in the
catalogue, or whose {0}-placeholders differ, are rejected and reported.  Existing entries
are kept unless the part overrides them.  New locale files get a _meta block with
reviewed=false.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import extract as e

NAMES = {"zh-CN": "Simplified Chinese", "zh-TW": "Traditional Chinese", "es": "Spanish", "de": "German",
         "fr": "French", "ja": "Japanese", "pt-BR": "Brazilian Portuguese", "ru": "Russian"}


def main():
    code, parts = sys.argv[1], sys.argv[2:]
    keys = e.collect()
    path = os.path.join(e.LOC, code + ".json")
    if os.path.exists(path):
        doc = json.load(open(path, encoding="utf-8"))
    else:
        doc = {"_meta": {"language": NAMES.get(code, code), "reviewed": False,
                         "author": "machine-assisted (Claude)", "coverage": 0}, "strings": {}, "rules": []}
    s = doc["strings"]
    bad = stale = 0
    for f in parts:
        try:
            j = json.load(open(f, encoding="utf-8"))
        except Exception as ex:
            print("BAD JSON", f, ex)
            continue
        for a, b in j.items():
            if a not in keys:
                stale += 1
            elif not isinstance(b, str) or not b.strip() or e.ph(a) != e.ph(b):
                bad += 1
                print("placeholder/empty:", a, "->", b)
            else:
                s[a] = b
    doc["strings"] = dict(sorted(s.items(), key=lambda x: x[0].lower()))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(e.dumps(doc))
    print(code, len(s), "strings; stale", stale, "rejected", bad)


if __name__ == "__main__":
    main()
