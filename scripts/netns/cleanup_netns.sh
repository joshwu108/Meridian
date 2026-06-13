#!/usr/bin/env bash
#
# DEBUG-ONLY. The Go test harness (test/harness/netns.go) is the AUTHORITATIVE
# netns fixture used by CI and the integration suite. This script exists only so
# a developer can reproduce that topology by hand while debugging; it is not on
# the CI fixture path (asserted by test/harness/netns_scripts_test.go). Keep its
# command sequence in sync with the harness — see docs/NETNS_SCRIPTS.md (C-4/D-4).
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: cleanup_netns.sh <namespace> [host_veth]

Best-effort cleanup helper for integration environments:
  - removes clsact on host_veth (if provided)
  - deletes host_veth (which also deletes its peer)
  - deletes namespace

Environment:
  DRY_RUN=1   Print commands instead of executing them.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

namespace="$1"
host_veth="${2:-}"
dry_run="${DRY_RUN:-0}"

run_best_effort() {
  echo "+ $*"
  if [[ "$dry_run" == "1" ]]; then
    return 0
  fi
  "$@" || true
}

if [[ -n "$host_veth" ]]; then
  run_best_effort tc qdisc del dev "$host_veth" clsact
  run_best_effort ip link del "$host_veth"
fi

run_best_effort ip netns del "$namespace"
