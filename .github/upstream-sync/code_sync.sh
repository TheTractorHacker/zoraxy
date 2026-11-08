#!/usr/bin/env bash
# Fork-only: local equivalent of .github/workflows/fork-upstream-code-sync.yml.
# Use it when the workflow cannot push (upstream changed workflow files and no
# UPSTREAM_SYNC_TOKEN is set). Needs git, go and an authenticated `gh` with the
# `workflow` scope. Never force-pushes, never touches your working tree's branch.
set -euo pipefail

UPSTREAM=${UPSTREAM:-tobychui/zoraxy}
FORK=${FORK:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}
cd "$(git rev-parse --show-toplevel)"

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "https://github.com/$UPSTREAM.git"
git remote set-url --push upstream DISABLED
git fetch --no-tags upstream
git fetch origin

BASE=$(gh api "repos/$FORK" -q .default_branch)
UP_BRANCH=$(gh api "repos/$UPSTREAM" -q .default_branch)
UP_SHA=$(git rev-parse "upstream/$UP_BRANCH")
BEHIND=$(git rev-list --count "origin/$BASE..$UP_SHA")
BRANCH="upstream-sync/${UP_SHA:0:12}"
echo "$FORK:$BASE is missing $BEHIND commits from $UPSTREAM@$UP_BRANCH ($UP_SHA)"
[ "$BEHIND" = 0 ] && exit 0

if [ "$(gh pr list --repo "$FORK" --head "$BRANCH" --state open --json number -q length)" != 0 ]; then
  echo "A PR for $BRANCH is already open."; exit 0
fi

# Test-merge in a throwaway worktree so local work is never disturbed.
WT=$(mktemp -d)
trap 'git worktree remove --force "$WT" >/dev/null 2>&1 || true' EXIT
git worktree add --detach -q "$WT" "origin/$BASE"
REPORT=$(mktemp)
if git -C "$WT" -c user.name=sync -c user.email=sync@localhost merge --no-ff --no-commit -q "$UP_SHA" 2>/dev/null; then
  echo "### Test merge: clean" > "$REPORT"
  for step in "build ./..." "vet ./..." "test ./..."; do
    if (cd "$WT/src" && go $step >/dev/null 2>&1); then r=pass; else r="**FAIL**"; fi
    echo "- go $step: $r" >> "$REPORT"
  done
else
  { echo "### Test merge: CONFLICTS"; git -C "$WT" diff --name-only --diff-filter=U | sed 's/^/- `/; s/$/`/'; } > "$REPORT"
fi
cat "$REPORT"

if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null; then
  echo "Branch $BRANCH already exists on $FORK; not touching it."
else
  git push origin "$UP_SHA:refs/heads/$BRANCH"
fi
{ echo "Brings in **$BEHIND** commits from \`$UPSTREAM\`@\`$UP_BRANCH\` (\`${UP_SHA:0:12}\`)."; echo; cat "$REPORT"
  echo; echo "Review against custom code before merging; deploy by hand."; } > "$REPORT.body"
gh pr create --repo "$FORK" --base "$BASE" --head "$BRANCH" \
  --title "Upstream sync: $UPSTREAM@${UP_SHA:0:12}" --body-file "$REPORT.body"
