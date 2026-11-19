#!/usr/bin/env bash
# Run every gate, then rebase on dev and push. Stops at the first failure. Never pipe a gate.
set -euo pipefail
cd "$(dirname "$0")/.."
# Refuse during a hold (finding 3), with uncommitted changes (finding 4: the gates must check what is
# pushed), and check every commit's Agent: trailer before the push, while it can still be amended (finding 5).
[ -e board/HOLD.md ] && { echo "board/HOLD.md exists: no release while it does" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "uncommitted changes: commit or stash them first" >&2; exit 1; }
git fetch -q origin dev
# The signature check runs as it stood at the last release (origin/dev), never from the tree being pushed, so a push
# cannot change its own checker (videos.b@'s finding via conductor.b@, 19 Nov 2026, 14:01 UTC).
SIGTMP=$(mktemp -d); trap 'rm -rf "$SIGTMP"' EXIT
sigcheck() { git show "origin/dev:scripts/check-signatures.mjs" > "$SIGTMP/check-signatures.mjs"; node "$SIGTMP/check-signatures.mjs" "$@"; }
node scripts/build.mjs
node scripts/validate.mjs
node scripts/test-leak-scan.mjs
node scripts/test-pulse-daily.mjs
node scripts/test-check-signatures.mjs
node scripts/leak-scan.mjs
node scripts/check-commits.mjs origin/dev HEAD
sigcheck origin/dev HEAD
for i in 1 2 3 4 5; do
  git fetch -q origin dev
  git rebase -q origin/dev
  # One gate per line: under set -e a failure inside an && chain does not stop the script (specialist.code@ finding 1).
  node scripts/build.mjs >/dev/null
  node scripts/validate.mjs >/dev/null
  node scripts/test-leak-scan.mjs >/dev/null
  node scripts/test-pulse-daily.mjs >/dev/null
  node scripts/test-check-signatures.mjs >/dev/null
  node scripts/leak-scan.mjs >/dev/null
  node scripts/check-commits.mjs origin/dev HEAD >/dev/null
  sigcheck origin/dev HEAD >/dev/null
  if git -c push.negotiate=true push -q origin HEAD:dev; then echo "released $(git rev-parse --short HEAD) to dev"; exit 0; fi
  sleep $((i * 3))
done
echo "release failed after 5 attempts" >&2; exit 1
