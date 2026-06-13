#!/usr/bin/env bash
# check-mer-ticket-refs.sh — MER-45 commit→ticket traceability gate.
#
# Ensures implementation commits (feat/fix/refactor) name at least one MER-<n>
# ticket in the subject or body. Multi-ticket commits must list every ticket
# they implement somewhere in the subject+body (enforced by requiring ≥1 MER
# ref; authors are responsible for listing all IDs per CONTRIBUTING.md).
#
# Usage:
#   scripts/check-mer-ticket-refs.sh              # commits in origin/main..HEAD
#   scripts/check-mer-ticket-refs.sh <rev-range>  # e.g. abc123..def456
#
# Skips merge commits and non-implementation prefixes (docs, chore, ci, test, …).
set -euo pipefail

rev_range="${1:-}"
if [[ -z "$rev_range" ]]; then
  if git rev-parse --verify origin/main >/dev/null 2>&1; then
    rev_range="origin/main..HEAD"
  elif git rev-parse --verify main >/dev/null 2>&1; then
    rev_range="main..HEAD"
  else
    # Shallow clone or first commit: check HEAD only.
    rev_range="HEAD"
  fi
fi

if ! git rev-parse --verify "${rev_range%%..*}" >/dev/null 2>&1; then
  echo "check-mer-ticket-refs: no commits to check in range '$rev_range' (ok)"
  exit 0
fi

# Prefixes that carry implementation intent and must cite a ticket.
impl_re='^(feat|fix|refactor)(\([^)]+\))?:'

# Prefixes exempt from the MER requirement (process/docs/infra only).
exempt_re='^(docs|chore|ci|test|style|perf|build|revert|merge)(\([^)]+\))?:'

fail=0
while IFS= read -r sha; do
  [[ -z "$sha" ]] && continue

  parents=$(git rev-list --parents -n 1 "$sha" | awk '{print NF-1}')
  if [[ "$parents" -gt 1 ]]; then
    continue
  fi

  subject=$(git log -1 --format='%s' "$sha")
  body=$(git log -1 --format='%b' "$sha")
  combined="${subject}
${body}"

  if [[ "$subject" =~ $exempt_re ]]; then
    continue
  fi

  if [[ "$subject" =~ $impl_re ]]; then
    if ! grep -qE 'MER-[0-9]+' <<<"$combined"; then
      echo "ERROR: $sha — implementation commit missing MER-<n> reference"
      echo "       subject: $subject"
      echo "       feat/fix/refactor commits must name ≥1 ticket (see CONTRIBUTING.md)"
      fail=1
    fi
  fi
done < <(git rev-list --no-merges "$rev_range" 2>/dev/null || true)

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "check-mer-ticket-refs: FAILED — add MER-<n> to subject or body"
  exit 1
fi

echo "check-mer-ticket-refs: ok ($rev_range)"
