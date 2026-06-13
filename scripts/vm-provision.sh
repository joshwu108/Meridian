#!/usr/bin/env bash
# Run test/vm/provision.sh inside the Meridian Lima VM (idempotent).
# macOS only; no-op on Linux.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
	exit 0
fi

instance="${MERIDIAN_LIMA_INSTANCE:-meridian}"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v limactl &>/dev/null; then
	echo "ERROR: limactl not found. Run: make vm-install" >&2
	exit 1
fi

status="$(limactl list "$instance" 2>/dev/null | awk -v n="$instance" '$1==n { print $2; exit }')"
if [[ "$status" != "Running" ]]; then
	echo "ERROR: Lima '$instance' is not Running (status=${status:-missing}). Run: make vm-up" >&2
	exit 1
fi

echo "==> Provisioning Meridian toolchain in Lima '$instance' (REPO_ROOT=$repo_root)..."
limactl shell "$instance" -- sudo env REPO_ROOT="$repo_root" bash "$repo_root/test/vm/provision.sh"
