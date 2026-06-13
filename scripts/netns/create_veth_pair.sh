#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: create_veth_pair.sh <namespace> <host_veth> <peer_veth> <host_cidr> <peer_cidr> [--no-clsact]

Creates a veth pair, moves one side into the namespace, assigns addresses, and
brings interfaces up.

Environment:
  DRY_RUN=1   Print commands instead of executing them.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 5 || $# -gt 6 ]]; then
  usage >&2
  exit 1
fi

namespace="$1"
host_veth="$2"
peer_veth="$3"
host_cidr="$4"
peer_cidr="$5"
attach_clsact="1"

if [[ $# -eq 6 ]]; then
  if [[ "$6" != "--no-clsact" ]]; then
    usage >&2
    exit 1
  fi
  attach_clsact="0"
fi

dry_run="${DRY_RUN:-0}"

run() {
  echo "+ $*"
  if [[ "$dry_run" == "1" ]]; then
    return 0
  fi
  "$@"
}

run ip link add "$host_veth" type veth peer name "$peer_veth"
run ip link set "$peer_veth" netns "$namespace"
run ip addr add "$host_cidr" dev "$host_veth"
run ip link set "$host_veth" up
run ip netns exec "$namespace" ip addr add "$peer_cidr" dev "$peer_veth"
run ip netns exec "$namespace" ip link set "$peer_veth" up
run ip netns exec "$namespace" ip link set lo up

if [[ "$attach_clsact" == "1" ]]; then
  run tc qdisc replace dev "$host_veth" clsact
fi
