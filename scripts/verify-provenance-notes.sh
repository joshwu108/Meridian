#!/usr/bin/env bash
# verify-provenance-notes.sh — MER-45: assert backfilled provenance exists.
#
# Provenance is recorded two ways:
#   1. git notes on the commit SHA (preferred; push refs/notes/commits)
#   2. committed mirror files under docs/provenance/<sha>.note (CI-safe)
#
# Usage: scripts/verify-provenance-notes.sh
set -euo pipefail

root=$(git rev-parse --show-toplevel)
mirror_dir="${root}/docs/provenance"

required=(
  "754e2ee"
  "96f9fdb"
)

fail=0
for sha_prefix in "${required[@]}"; do
  mirror="${mirror_dir}/${sha_prefix}.note"
  if [[ ! -s "$mirror" ]]; then
    echo "ERROR: missing provenance mirror ${mirror}"
    fail=1
    continue
  fi
  expected=$(tr -d '\n' <"$mirror" | sed 's/[[:space:]]*$//')

  full_sha=$(git rev-parse --verify "${sha_prefix}^{commit}" 2>/dev/null) || {
    echo "ERROR: commit ${sha_prefix} not found in this clone"
    fail=1
    continue
  }

  if note=$(git notes show "$full_sha" 2>/dev/null); then
    note_trimmed=$(printf '%s' "$note" | tr -d '\n' | sed 's/[[:space:]]*$//')
    if [[ "$note_trimmed" != "$expected" ]]; then
      echo "ERROR: git note on ${sha_prefix} diverges from ${mirror}"
      echo "       note:   ${note_trimmed}"
      echo "       mirror: ${expected}"
      fail=1
      continue
    fi
    echo "ok: ${sha_prefix} — git note matches mirror"
  else
    echo "ok: ${sha_prefix} — mirror present (git note not fetched; run git fetch origin refs/notes/commits:refs/notes/commits)"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "verify-provenance-notes: FAILED — see docs/provenance/mislabeled-commits.md"
  exit 1
fi

echo "verify-provenance-notes: ok"
