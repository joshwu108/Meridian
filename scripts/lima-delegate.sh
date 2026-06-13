#!/usr/bin/env bash
# Delegate a Makefile target to the Meridian Lima VM when the host is not Linux.
#
# Usage: scripts/lima-delegate.sh <make-target>
#
# On Linux (or when MERIDIAN_IN_LIMA=1 inside the guest), runs:
#   make <make-target>
# On macOS with a running Lima instance, runs the same command in-guest at the
# current working directory (home mount preserves the host path).
set -euo pipefail

target="${1:?usage: lima-delegate.sh <make-target>}"
shift || true

goos="$(go env GOOS 2>/dev/null || uname | tr '[:upper:]' '[:lower:]')"
if [[ "$goos" == "linux" || "${MERIDIAN_IN_LIMA:-}" == "1" ]]; then
	exec make "$target" "$@"
fi

instance="${MERIDIAN_LIMA_INSTANCE:-meridian}"
repo_root="$(pwd)"
script_dir="$(cd "$(dirname "$0")" && pwd)"

if ! command -v limactl &>/dev/null; then
	echo "ERROR: '$target' requires Linux (eBPF/netns). Host GOOS=$goos and limactl is not installed." >&2
	if [[ "$goos" == "darwin" ]]; then
		echo "       Run: make vm-install && make vm-up" >&2
	else
		echo "       Install Lima (https://lima-vm.io) or use a Linux host." >&2
	fi
	exit 1
fi

status="$(limactl list "$instance" 2>/dev/null | awk -v n="$instance" '$1==n { print $2; exit }')"
if [[ -z "$status" ]]; then
	echo "ERROR: Lima instance '$instance' not found." >&2
	echo "       Run: make vm-up" >&2
	exit 1
fi
if [[ "$status" != "Running" ]]; then
	echo "ERROR: Lima '$instance' is $status (need Running)." >&2
	echo "       Run: make vm-up" >&2
	exit 1
fi

# First-boot Lima provision only runs if the repo was visible at create time.
# Ensure toolchain exists before delegating (installs make, go, clang, bpftool).
if ! limactl shell "$instance" -- bash -lc "export PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin; command -v make >/dev/null && command -v go >/dev/null"; then
	echo "==> VM toolchain missing; provisioning..."
	MERIDIAN_LIMA_INSTANCE="$instance" bash "$script_dir/vm-provision.sh"
fi

guest_path="export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
echo "==> Host GOOS=$goos; delegating 'make $target' to Lima $instance"
exec limactl shell "$instance" -- bash -lc "cd '$repo_root' && $guest_path && MERIDIAN_IN_LIMA=1 make '$target'"
