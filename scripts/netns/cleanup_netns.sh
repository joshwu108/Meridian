#!/usr/bin/env bash
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
