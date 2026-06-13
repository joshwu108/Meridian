#!/usr/bin/env bash
# Start (or create) the Meridian Lima dev VM. macOS only.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
	echo "vm-up: not needed on Linux."
	exit 0
fi

instance="${MERIDIAN_LIMA_INSTANCE:-meridian}"
yaml="test/vm/meridian.yaml"
script_dir="$(cd "$(dirname "$0")" && pwd)"

if ! command -v limactl &>/dev/null; then
	echo "ERROR: limactl not found." >&2
	echo "       Run: make vm-install   (installs Lima via Homebrew)" >&2
	exit 1
fi

if limactl list "$instance" 2>/dev/null | awk -v n="$instance" '$1==n { found=1 } END { exit !found }'; then
	echo "Starting existing Lima instance '$instance'..."
	limactl start "$instance"
else
	echo "Creating Lima instance '$instance' from $yaml (first boot may take a few minutes)..."
	limactl start --name="$instance" "$yaml"
fi

# Lima's yaml provision only runs at create time and may miss the repo mount.
# Always run the idempotent provision script with an explicit REPO_ROOT.
MERIDIAN_LIMA_INSTANCE="$instance" bash "$script_dir/vm-provision.sh"

echo "VM ready. Run privileged tests from macOS:"
echo "  make test-linux"
