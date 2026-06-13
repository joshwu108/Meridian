#!/usr/bin/env bash
# Install Lima on macOS so eBPF/netns targets can auto-delegate from make.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
	echo "vm-install: not needed on Linux (run make targets directly)."
	exit 0
fi

if command -v limactl &>/dev/null; then
	echo "Lima already installed: $(limactl --version 2>/dev/null | head -1)"
	exit 0
fi

if ! command -v brew &>/dev/null; then
	echo "ERROR: Homebrew is required to install Lima on macOS." >&2
	echo "       https://brew.sh" >&2
	echo "       Then: brew install lima" >&2
	exit 1
fi

echo "Installing Lima via Homebrew..."
brew install lima
echo "Done. Next: make vm-up"
