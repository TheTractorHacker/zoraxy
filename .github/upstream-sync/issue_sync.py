#!/usr/bin/env python3
"""Mirror issues and comments from an upstream GitHub repository into a fork.

Fork-specific tooling for TheTractorHacker/zoraxy. Not part of upstream Zoraxy.

Modes
  import  Copy every upstream issue (open and closed) that is not yet mirrored.
          Safe to re-run: it resumes where it stopped and never duplicates.
  sync    Copy only upstream changes since the newest mirrored update: new
          issues, edits, state and label changes, and new or edited comments.
          Refuses to run until an import exists and caps how many issues it
          will create in one run (--max-creates).

How state is kept
  Every mirrored issue and comment carries a hidden marker block:

    <!-- upstream-sync:begin -->   ...managed content...   <!-- upstream-sync:end -->
    <!-- upstream-sync:meta {json} -->

  The meta JSON records the upstream id and the last state the sync applied.
  The mapping between upstream and fork numbers is rebuilt from these markers
  on every run, so no state file is needed and an interrupted run can never
  create duplicates (anything GitHub accepted already carries its marker).

What is never touched
  * The upstream repository. Only GET requests go to it; every write goes to
    --target, which must differ from --upstream.
  * Issues and comments without a marker (your own content).
  * Text outside the markers in a mirrored issue (your notes).
  * A managed block you edited by hand: it is reported as a conflict and left
    alone. Titles, states, labels and milestones you changed on the fork are
    left alone too; the sync only applies a field when upstream changed it and
    the fork still holds the value the sync last wrote.

Etiquette
  * @mentions are wrapped in code spans so original authors are not notified.
  * Links to issues, PRs and discussions go through redirect.github.com, which
    GitHub provides so that automated copies do not post "mentioned this
    issue" back-references on the original threads. Bare #123 references are
    rewritten to point at upstream, not at the fork's own numbering.

Authentication: GH_TOKEN or GITHUB_TOKEN, else `gh auth token`. The token is
never printed.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
REDIRECT = "https://redirect.github.com"
BEGIN = "<!-- upstream-sync:begin -->"
END = "<!-- upstream-sync:end -->"
META_PREFIX = "<!-- upstream-sync:meta "
MANAGED_RE = re.compile(
    r"<!-- upstream-sync:begin -->\n(.*?)\n<!-- upstream-sync:end -->\n<!-- upstream-sync:meta (\{.*?\}) -->",
    re.S,
)
LOOSE_META_RE = re.compile(r"<!-- upstream-sync:meta (\{.*?\}) -->", re.S)
IMPORT_LABEL = {"name": "upstream", "color": "ededed",
                "description": "Mirrored from the upstream Zoraxy repository"}
MAX_BODY = 65536
PER_ISSUE_FETCH_LIMIT = 40  # above this, list comments repo-wide instead of per issue


# --------------------------------------------------------------------------- API

class GitHubError(Exception):
    def __init__(self, status, method, url, detail):
        super().__init__(f"{method} {url} -> HTTP {status}: {detail}")
        self.status = status


class GitHub:
    """Minimal REST client with pacing for writes and rate-limit handling."""

    def __init__(self, token, write_interval, dry_run, log):
        self._token = token
        self.write_interval = write_interval
        self.dry_run = dry_run
        self.log = log
        self._last_write = 0.0
        self.reads = 0
        self.writes = 0

    def request(self, method, path, body=None):
        url = path if path.startswith("http") else API + path
        is_write = method != "GET"
        if is_write and self.dry_run:
            self.log(f"  [dry-run] {method} {url}")
            return None, {}
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(1, 9):
            if is_write:
                wait = self._last_write + self.write_interval - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "zoraxy-fork-issue-sync",
                "Content-Type": "application/json",
            })
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = resp.read()
                    self._count(is_write)
                    return (json.loads(raw) if raw else None), resp.headers
            except urllib.error.HTTPError as e:
                self._count(is_write)
                text = e.read().decode(errors="replace")
                if self._is_rate_limited(e, text):
                    delay = self._rate_limit_delay(e.headers, attempt)
                    self.log(f"  rate limited on {method} {url}; waiting {delay}s (attempt {attempt})")
                    time.sleep(delay)
                    continue  # a rate-limited request was not applied, so retrying is safe
                if e.code >= 500 and not is_write:
                    time.sleep(min(60, 2 ** attempt))
                    continue
                raise GitHubError(e.code, method, url, text[:300]) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if is_write:
                    # The write may have been applied. Do not retry; the next run
                    # rebuilds the mapping from markers and will not duplicate it.
                    raise GitHubError("network", method, url, str(e)) from None
                time.sleep(min(60, 2 ** attempt))
        raise GitHubError("retries-exhausted", method, url, "gave up after 8 attempts")

    def _count(self, is_write):
        if is_write:
            self.writes += 1
            self._last_write = time.monotonic()
        else:
            self.reads += 1

    @staticmethod
    def _is_rate_limited(e, text):
        if e.code == 429:
            return True
        return e.code == 403 and (
            e.headers.get("x-ratelimit-remaining") == "0"
            or e.headers.get("retry-after") is not None
            or "rate limit" in text.lower()
        )

    @staticmethod
    def _rate_limit_delay(headers, attempt):
        if headers.get("retry-after"):
            return int(headers["retry-after"]) + 1
        if headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset"):
            return max(5, int(headers["x-ratelimit-reset"]) - int(time.time()) + 5)
        return min(900, 60 * 2 ** (attempt - 1))  # secondary limit without hints

    def get(self, path):
        return self.request("GET", path)[0]

    def paginate(self, path, params=None):
        params = dict(params or {}, per_page=100)
        url = f"{API}{path}?{urllib.parse.urlencode(params)}"
        items = []
        while url:
            data, headers = self.request("GET", url)
            items.extend(data)
            url = None
            for part in (headers.get("Link") or "").split(","):
                if 'rel="next"' in part:
                    url = part[part.index("<") + 1:part.index(">")]
        return items


def resolve_token():
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        return subprocess.run(["gh", "auth", "token"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("No token: set GH_TOKEN or sign in with `gh auth login`.")


# --------------------------------------------------------------------- rendering

CODE_RE = re.compile(r"(```.*?```|~~~.*?~~~|`[^`\n]+`)", re.S)
GH_LINK_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([\w.-]+/[\w.-]+)/(issues|pull|discussions)/(\d+)")
XREPO_REF_RE = re.compile(r"(?<![\w/\[.-])([A-Za-z0-9][\w.-]*/[\w.-]+)#(\d+)\b")
BARE_REF_RE = re.compile(r"(?<![\w/&#\[])#(\d{1,6})\b")
MENTION_RE = re.compile(r"(?<![\w`/.@])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[\w.-]+)?)")


def defuse_prose(text, upstream):
    text = GH_LINK_RE.sub(lambda m: f"{REDIRECT}/{m[1]}/{m[2]}/{m[3]}", text)
    text = XREPO_REF_RE.sub(lambda m: f"[{m[1]}#{m[2]}]({REDIRECT}/{m[1]}/issues/{m[2]})", text)
    text = BARE_REF_RE.sub(lambda m: f"[#{m[1]}]({REDIRECT}/{upstream}/issues/{m[1]})", text)
    return MENTION_RE.sub(lambda m: f"`@{m[1]}`", text)


def defuse(text, upstream):
    """Neutralise mentions and cross-references outside code; leave code alone."""
    text = (text or "").replace("\r\n", "\n")
    parts = CODE_RE.split(text)
    for i in range(0, len(parts), 2):
        parts[i] = defuse_prose(parts[i], upstream)
    return "".join(parts)


def redirect(url):
    return url.replace("https://github.com/", f"{REDIRECT}/", 1)


def user_link(user):
    if not user:
        return "ghost (deleted account)"
    return f"[{user['login']}](https://github.com/{user['login']})"


def when(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def fit(text, budget):
    if len(text) <= budget:
        return text
    return text[:budget] + "\n\n> _Truncated: the original exceeds GitHub's size limit. See the upstream link above._"


def render_issue_block(issue, upstream):
    num = issue["number"]
    link = redirect(issue["html_url"])
    assoc = issue.get("author_association", "")
    rows = [
        ("Original issue", f"[{upstream}#{num}]({link})"),
        ("Author", user_link(issue["user"]) + (f" ({assoc.lower()})" if assoc in ("OWNER", "MEMBER", "COLLABORATOR") else "")),
        ("Opened", when(issue["created_at"])),
    ]
    if issue["state"] == "closed" and issue.get("closed_at"):
        reason = (issue.get("state_reason") or "completed").replace("_", " ")
        rows.append(("Closed", f"{when(issue['closed_at'])} ({reason})"))
    if issue.get("labels"):
        rows.append(("Labels", ", ".join(f"`{cell(l['name'])}`" for l in issue["labels"])))
    if issue.get("milestone"):
        rows.append(("Milestone", cell(issue["milestone"]["title"])))
    if issue.get("assignees"):
        rows.append(("Assignees", ", ".join(user_link(a) for a in issue["assignees"])))
    if issue.get("locked"):
        rows.append(("Locked", cell(issue.get("active_lock_reason") or "yes")))
    head = (
        f"> [!NOTE]\n> Mirrored from upstream [{upstream}#{num}]({link}) by the fork's issue sync. "
        "The section between the `upstream-sync` markers is updated automatically; "
        "put your own notes below it or in comments.\n\n"
        "| | |\n|---|---|\n" + "\n".join(f"| **{k}** | {v} |" for k, v in rows) + "\n\n---\n\n"
    )
    body = defuse(issue.get("body"), upstream).strip() or "_No description provided._"
    return head + fit(body, MAX_BODY - len(head) - 2000)


def render_comment_block(comment, upstream):
    head = (f"> **{user_link(comment['user'])}** commented upstream on {when(comment['created_at'])} "
            f"· [original comment]({redirect(comment['html_url'])})\n\n")
    body = defuse(comment.get("body"), upstream).strip() or "_Empty comment._"
    return head + fit(body, MAX_BODY - len(head) - 1000)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def compose(block, meta, prefix="", suffix=""):
    meta_json = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).replace(">", "\\u003e")
    return f"{prefix}{BEGIN}\n{block}\n{END}\n{META_PREFIX}{meta_json} -->{suffix}"


def parse_managed(body):
    """Return (prefix, block, meta, suffix, intact) or None if not a mirrored item."""
    body = (body or "").replace("\r\n", "\n")
    m = MANAGED_RE.search(body)
    if m:
        return body[:m.start()], m[1], json.loads(m[2]), body[m.end():], True
    loose = LOOSE_META_RE.search(body)
    if loose:  # markers were damaged by a manual edit; still mapped, never overwritten
        return "", "", json.loads(loose[1]), "", False
    return None


# ------------------------------------------------------------------------ syncer

class Syncer:
    def __init__(self, gh, upstream, target, args, log):
        self.gh, self.up, self.tgt, self.args, self.log = gh, upstream, target, args, log
        self.report = {k: [] for k in (
            "issues_created", "issues_updated", "issues_unchanged", "issues_skipped", "issues_conflict",
            "issues_failed", "comments_created", "comments_updated", "comments_unchanged",
            "comments_conflict", "comments_failed", "labels_created", "milestones_created")}
        self.index = {}           # upstream number -> fork issue dict + parsed managed tuple
        self.comment_index = {}   # upstream comment id -> (fork comment dict, parsed)
        self.comments_loaded = set()  # fork issue numbers whose comments are indexed
        self.fresh = set()        # fork issue numbers created in this run (no comments yet)
        self.label_names = set()
        self.milestones = {}      # title -> fork milestone number

    # -- safety and indexes -----------------------------------------------------

    def preflight(self):
        if self.up.lower() == self.tgt.lower():
            sys.exit("Refusing to run: --target is the upstream repository.")
        repo = self.gh.get(f"/repos/{self.tgt}")
        if not repo.get("has_issues"):
            sys.exit(f"Issues are disabled on {self.tgt}.")
        perms = repo.get("permissions") or {}
        if perms and not (perms.get("push") or perms.get("triage")):
            sys.exit(f"The token cannot write issues on {self.tgt}.")
        self.log(f"Upstream {self.up} (read only) -> target {self.tgt}")

    def load_index(self):
        items = self.gh.paginate(f"/repos/{self.tgt}/issues", {"state": "all"})
        # Oldest first, so if an item was ever mirrored twice the original copy wins.
        for item in sorted(items, key=lambda i: i["number"]):
            if "pull_request" in item:
                continue
            parsed = parse_managed(item.get("body"))
            if parsed and parsed[2].get("kind") == "issue":
                up_num = parsed[2]["number"]
                if up_num in self.index:
                    self.log(f"  warning: upstream #{up_num} is mirrored twice "
                             f"(fork #{self.index[up_num][0]['number']} and #{item['number']})")
                    continue
                self.index[up_num] = (item, parsed)
        self.log(f"Fork already mirrors {len(self.index)} upstream issues")

    def index_fork_comments(self, fork_numbers):
        todo = [n for n in fork_numbers if n not in self.comments_loaded and n not in self.fresh]
        if not todo:
            return
        if len(todo) > PER_ISSUE_FETCH_LIMIT:
            items = self.gh.paginate(f"/repos/{self.tgt}/issues/comments")
            self.comments_loaded.update(fork["number"] for fork, _ in self.index.values())
        else:
            items = []
            for n in todo:
                items += self.gh.paginate(f"/repos/{self.tgt}/issues/{n}/comments")
                self.comments_loaded.add(n)
        for c in items:
            parsed = parse_managed(c.get("body"))
            if parsed and parsed[2].get("kind") == "comment":
                self.comment_index.setdefault(parsed[2]["id"], (c, parsed))

    def ensure_labels_and_milestones(self, issues):
        self.label_names = {l["name"] for l in self.gh.paginate(f"/repos/{self.tgt}/labels")}
        wanted = {IMPORT_LABEL["name"]: IMPORT_LABEL}
        for i in issues:
            for l in i.get("labels", []):
                wanted.setdefault(l["name"], {"name": l["name"], "color": l.get("color") or "ededed",
                                              "description": (l.get("description") or "")[:100]})
        for name, spec in wanted.items():
            if name not in self.label_names:
                self.gh.request("POST", f"/repos/{self.tgt}/labels", spec)
                self.label_names.add(name)
                self.report["labels_created"].append(name)
        self.milestones = {m["title"]: m["number"] for m in
                           self.gh.paginate(f"/repos/{self.tgt}/milestones", {"state": "all"})}
        for i in issues:
            ms = i.get("milestone")
            if ms and ms["title"] not in self.milestones:
                spec = {"title": ms["title"], "state": ms["state"], "description": ms.get("description") or ""}
                if ms.get("due_on"):
                    spec["due_on"] = ms["due_on"]
                created, _ = self.gh.request("POST", f"/repos/{self.tgt}/milestones", spec)
                self.milestones[ms["title"]] = created["number"] if created else None
                self.report["milestones_created"].append(ms["title"])

    # -- issues -----------------------------------------------------------------

    def issue_meta(self, issue, block, applied_state):
        return {"v": 1, "kind": "issue", "id": issue["id"], "number": issue["number"],
                "updated_at": issue["updated_at"], "title": issue["title"], "state": applied_state,
                "labels": sorted(l["name"] for l in issue.get("labels", [])),
                "milestone": (issue.get("milestone") or {}).get("title"), "block_sha": sha(block)}

    def create_issue(self, issue):
        block = render_issue_block(issue, self.up)
        labels = sorted({l["name"] for l in issue.get("labels", [])} | {IMPORT_LABEL["name"]})
        payload = {"title": issue["title"], "labels": labels,
                   "body": compose(block, self.issue_meta(issue, block, "open"))}
        ms = issue.get("milestone")
        if ms and self.milestones.get(ms["title"]):
            payload["milestone"] = self.milestones[ms["title"]]
        created, _ = self.gh.request("POST", f"/repos/{self.tgt}/issues", payload)
        if created is None:  # dry run
            self.report["issues_created"].append({"upstream": issue["number"], "fork": None})
            return None
        num = created["number"]
        self.fresh.add(num)
        if issue["state"] == "closed":
            # Second write: close it and record the applied state in the marker.
            self.gh.request("PATCH", f"/repos/{self.tgt}/issues/{num}", {
                "state": "closed", "state_reason": issue.get("state_reason") or "completed",
                "body": compose(block, self.issue_meta(issue, block, "closed"))})
        self.report["issues_created"].append({"upstream": issue["number"], "fork": num,
                                              "state": issue["state"]})
        self.log(f"  created fork #{num} <- upstream #{issue['number']} ({issue['state']})")
        return num

    def update_issue(self, issue, fork, parsed):
        prefix, block, meta, suffix, intact = parsed
        num = fork["number"]
        if not intact or sha(block) != meta.get("block_sha"):
            self.report["issues_conflict"].append({"upstream": issue["number"], "fork": num,
                                                   "reason": "managed block edited on the fork; left untouched"})
            return
        new_block = render_issue_block(issue, self.up)
        patch, notes = {}, []
        # Title, state, labels, milestone: apply only upstream transitions, and only
        # if the fork still holds what the sync last wrote (respect manual changes).
        if issue["title"] != meta.get("title") and fork["title"] == meta.get("title"):
            patch["title"] = issue["title"]; notes.append("title")
        applied_state = meta.get("state")
        if issue["state"] != meta.get("state") and fork["state"] == meta.get("state"):
            patch["state"] = issue["state"]
            if issue["state"] == "closed":
                patch["state_reason"] = issue.get("state_reason") or "completed"
            applied_state = issue["state"]; notes.append("state")
        up_labels = sorted(l["name"] for l in issue.get("labels", []))
        if up_labels != meta.get("labels"):
            fork_labels = {l["name"] for l in fork.get("labels", [])}
            merged = (fork_labels - set(meta.get("labels", []))) | set(up_labels) | {IMPORT_LABEL["name"]}
            patch["labels"] = sorted(merged); notes.append("labels")
        up_ms = (issue.get("milestone") or {}).get("title")
        fork_ms = (fork.get("milestone") or {}).get("title")
        if up_ms != meta.get("milestone") and fork_ms == meta.get("milestone"):
            patch["milestone"] = self.milestones.get(up_ms) if up_ms else None; notes.append("milestone")
        new_meta = self.issue_meta(issue, new_block, applied_state)
        if new_block != block:
            notes.append("body")
        if not notes and meta.get("updated_at") == issue["updated_at"]:
            self.report["issues_unchanged"].append(issue["number"])
            return
        patch["body"] = compose(new_block, new_meta, prefix, suffix)
        self.gh.request("PATCH", f"/repos/{self.tgt}/issues/{num}", patch)
        self.report["issues_updated"].append({"upstream": issue["number"], "fork": num,
                                              "changed": notes or ["sync metadata"]})
        self.log(f"  updated fork #{num} <- upstream #{issue['number']}: {', '.join(notes) or 'metadata'}")

    # -- comments ---------------------------------------------------------------

    def sync_comments(self, up_num, fork_num, comments):
        self.index_fork_comments([fork_num])
        for c in sorted(comments, key=lambda c: c["created_at"]):
            try:
                block = render_comment_block(c, self.up)
                meta = {"v": 1, "kind": "comment", "id": c["id"], "issue": up_num,
                        "updated_at": c["updated_at"], "block_sha": sha(block)}
                existing = self.comment_index.get(c["id"])
                if not existing:
                    created, _ = self.gh.request("POST", f"/repos/{self.tgt}/issues/{fork_num}/comments",
                                                 {"body": compose(block, meta)})
                    self.report["comments_created"].append({"upstream": c["id"], "fork": (created or {}).get("id"),
                                                            "issue": up_num})
                    if created:
                        self.comment_index[c["id"]] = (created, parse_managed(created["body"]))
                    continue
                fork_c, (prefix, old_block, old_meta, suffix, intact) = existing
                if old_meta.get("updated_at") == c["updated_at"] or old_block == block:
                    self.report["comments_unchanged"].append(c["id"])
                elif not intact or sha(old_block) != old_meta.get("block_sha"):
                    self.report["comments_conflict"].append({"upstream": c["id"], "fork": fork_c["id"]})
                else:
                    self.gh.request("PATCH", f"/repos/{self.tgt}/issues/comments/{fork_c['id']}",
                                    {"body": compose(block, meta, prefix, suffix)})
                    self.report["comments_updated"].append({"upstream": c["id"], "fork": fork_c["id"]})
            except GitHubError as e:
                self.report["comments_failed"].append({"upstream": c["id"], "issue": up_num, "error": str(e)})
                self.log(f"  FAILED comment {c['id']} on upstream #{up_num}: {e}")

    # -- run --------------------------------------------------------------------

    def fetch_upstream(self, mode):
        params = {"state": "all", "sort": "created", "direction": "asc"}
        since = None
        if mode == "sync":
            if not self.index:
                sys.exit("Nothing mirrored yet: run `import` (with approval) before `sync`.")
            newest = max(parsed[2]["updated_at"] for _, parsed in self.index.values())
            since = (datetime.fromisoformat(newest.replace("Z", "+00:00")) - timedelta(minutes=5)
                     ).strftime("%Y-%m-%dT%H:%M:%SZ")
            params = {"state": "all", "since": since, "sort": "updated", "direction": "asc"}
            self.log(f"Looking for upstream changes since {since}")
        if self.args.only:
            items = [self.gh.get(f"/repos/{self.up}/issues/{n}") for n in self.args.only]
        else:
            items = self.gh.paginate(f"/repos/{self.up}/issues", params)
        issues = []
        for i in items:
            if "pull_request" in i:
                self.report["issues_skipped"].append({"upstream": i["number"], "reason": "pull request"})
            else:
                issues.append(i)
        issues.sort(key=lambda i: i["number"])
        if self.args.limit:
            pending = [i for i in issues if i["number"] not in self.index]
            keep = {i["number"] for i in pending[:self.args.limit]}
            issues = [i for i in issues if i["number"] in keep or i["number"] in self.index]
        return issues, since

    def fetch_upstream_comments(self, issues, since):
        by_issue = {}
        if since:
            items = self.gh.paginate(f"/repos/{self.up}/issues/comments", {"since": since})
        elif len(issues) <= PER_ISSUE_FETCH_LIMIT:
            items = []
            for i in issues:
                if i.get("comments"):
                    items += self.gh.paginate(f"/repos/{self.up}/issues/{i['number']}/comments")
        else:
            items = self.gh.paginate(f"/repos/{self.up}/issues/comments")
        for c in items:
            by_issue.setdefault(int(c["issue_url"].rsplit("/", 1)[1]), []).append(c)
        return by_issue

    def run(self, mode):
        self.preflight()
        self.load_index()
        issues, since = self.fetch_upstream(mode)
        new = [i for i in issues if i["number"] not in self.index]
        self.log(f"Upstream issues in scope: {len(issues)} ({len(new)} not yet mirrored)")
        if mode == "sync" and len(new) > self.args.max_creates:
            sys.exit(f"Refusing to create {len(new)} issues in one sync (cap {self.args.max_creates}). "
                     "Run `import` instead, or raise --max-creates.")
        if mode == "import" and not self.args.yes and not self.args.dry_run and len(new) > 3:
            sys.exit(f"About to create {len(new)} issues. Re-run with --yes to confirm.")
        self.ensure_labels_and_milestones(issues)
        comments = self.fetch_upstream_comments(issues, since)
        mapped_with_comments = [self.index[n][0]["number"] for n in comments if n in self.index]
        if len(mapped_with_comments) > PER_ISSUE_FETCH_LIMIT:
            self.index_fork_comments(mapped_with_comments)
        for issue in issues:
            n = issue["number"]
            try:
                if n in self.index:
                    fork, parsed = self.index[n]
                    self.update_issue(issue, fork, parsed)
                    fork_num = fork["number"]
                else:
                    fork_num = self.create_issue(issue)
            except GitHubError as e:
                self.report["issues_failed"].append({"upstream": n, "error": str(e)})
                self.log(f"  FAILED upstream #{n}: {e}")
                continue
            if fork_num and comments.get(n):
                self.sync_comments(n, fork_num, comments[n])
        return self.report


def summarize(report, gh, mode, upstream, target, started):
    counts = {k: len(v) for k, v in report.items()}
    lines = [f"## Upstream issue {mode}: {upstream} -> {target}", "",
             f"Started {started:%Y-%m-%d %H:%M UTC}, API reads {gh.reads}, writes {gh.writes}"
             + (" (dry run: no writes sent)" if gh.dry_run else ""), "",
             "| Item | Count |", "|---|---|"]
    lines += [f"| {k.replace('_', ' ')} | {v} |" for k, v in counts.items()]
    for key in ("issues_failed", "comments_failed", "issues_conflict", "comments_conflict"):
        if report[key]:
            lines += ["", f"### {key.replace('_', ' ')}", ""]
            lines += [f"- `{json.dumps(x)}`" for x in report[key][:200]]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["import", "sync"])
    ap.add_argument("--upstream", default="tobychui/zoraxy")
    ap.add_argument("--target", default=os.environ.get("GITHUB_REPOSITORY"),
                    help="fork to write to (default: $GITHUB_REPOSITORY)")
    ap.add_argument("--only", type=lambda s: [int(x) for x in s.split(",")],
                    help="comma-separated upstream issue numbers")
    ap.add_argument("--limit", type=int, help="create at most N new issues this run")
    ap.add_argument("--max-creates", type=int, default=50, help="sync mode safety cap")
    ap.add_argument("--write-interval", type=float, default=7.5,
                    help="seconds between writes; 7.5 keeps under GitHub's ~500 content writes/hour")
    ap.add_argument("--dry-run", action="store_true", help="read everything, write nothing")
    ap.add_argument("--yes", action="store_true", help="confirm creating more than 3 issues")
    ap.add_argument("--report-dir", default=".")
    args = ap.parse_args()
    if not args.target:
        sys.exit("--target is required")

    # One run at a time per machine: two concurrent runs would both create the
    # same not-yet-mirrored issues. (In Actions, the workflow's concurrency group
    # does the same job.)
    os.makedirs(args.report_dir, exist_ok=True)
    lock = open(os.path.join(args.report_dir, ".issue-sync.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("Another issue sync is already running (lock held in --report-dir).")

    started = datetime.now(timezone.utc)
    log = lambda msg: print(msg, flush=True)
    gh = GitHub(resolve_token(), args.write_interval, args.dry_run, log)
    syncer = Syncer(gh, args.upstream, args.target, args, log)
    try:
        report = syncer.run(args.mode)
    finally:
        report = syncer.report
        summary = summarize(report, gh, args.mode, args.upstream, args.target, started)
        os.makedirs(args.report_dir, exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        with open(os.path.join(args.report_dir, f"issue-{args.mode}-{stamp}.json"), "w") as f:
            json.dump(report, f, indent=2)
        with open(os.path.join(args.report_dir, f"issue-{args.mode}-{stamp}.md"), "w") as f:
            f.write(summary)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
                f.write(summary)
        print("\n" + summary)
    sys.exit(1 if report["issues_failed"] or report["comments_failed"] else 0)


if __name__ == "__main__":
    main()
