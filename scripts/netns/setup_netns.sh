#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: setup_netns.sh <namespace>

Creates a Linux network namespace and brings loopback up.

Environment:
  DRY_RUN=1   Print commands instead of executing them.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

namespace="$1"
dry_run="${DRY_RUN:-0}"

run() {
  echo "+ $*"
  if [[ "$dry_run" == "1" ]]; then
    return 0
  fi
  "$@"
}

if [[ "$dry_run" != "1" ]] && ip netns list | awk '{print $1}' | grep -qx "$namespace"; then
  echo "namespace '$namespace' already exists; skipping create"
else
  run ip netns add "$namespace"
fi

run ip netns exec "$namespace" ip link set lo up
