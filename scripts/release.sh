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
[ "$(git rev-parse --is-shallow-repository)" = "false" ] || { echo "a shallow clone: fetch the whole history first" >&2; exit 1; }
SIGTMP=$(mktemp -d); trap 'rm -rf "$SIGTMP"' EXIT
# Every security check (signatures, trailers, leak scan) runs as it stood at the last release, never from the pushed tree
# (security@'s control 7 widened, 19 Nov 2026). A missing trusted copy stops the release: git show fails under set -e.
trusted() { local f="$1"; shift; git show "origin/dev:scripts/$f" > "$SIGTMP/$f"; node "$SIGTMP/$f" "$@"; }
sigcheck() { trusted check-signatures.mjs "$@"; }
node scripts/build.mjs
node scripts/validate.mjs
node scripts/test-leak-scan.mjs
node scripts/test-pulse-daily.mjs
node scripts/test-check-signatures.mjs
node scripts/test-ptmap.mjs
trusted leak-scan.mjs
trusted check-commits.mjs origin/dev HEAD
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
  node scripts/test-ptmap.mjs >/dev/null
  trusted leak-scan.mjs >/dev/null
  trusted check-commits.mjs origin/dev HEAD >/dev/null
  sigcheck origin/dev HEAD >/dev/null
  if git -c push.negotiate=true push -q origin HEAD:dev; then echo "released $(git rev-parse --short HEAD) to dev"; exit 0; fi
  sleep $((i * 3))
done
echo "release failed after 5 attempts" >&2; exit 1
