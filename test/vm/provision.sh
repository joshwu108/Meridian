#!/usr/bin/env bash
# test/vm/provision.sh — Lima provisioning for the Meridian eBPF dev VM.
#
# Installs the eBPF toolchain (clang/LLVM >= 15, bpftool, libbpf, Go >= 1.22),
# verifies versions and required kernel features, and generates vmlinux.h.
#
# Idempotent: safe to re-run. Exits non-zero on any unmet hard requirement.

set -euo pipefail

CLANG_VERSION="${CLANG_VERSION:-17}"   # >= 15 required; 17 pins bpf2go output
GO_VERSION="${GO_VERSION:-1.22.4}"
GO_MIN_MINOR=22
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
VMLINUX_H="${REPO_ROOT}/bpf/include/vmlinux.h"

log()  { printf '\033[36m[provision]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[provision] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || fail "Must run on Linux (inside the Lima VM)."

# --- APT packages ----------------------------------------------------------
log "Installing eBPF toolchain packages (clang-${CLANG_VERSION}, bpftool, libbpf)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git make \
  "clang-${CLANG_VERSION}" "llvm-${CLANG_VERSION}" \
  libbpf-dev \
  linux-tools-common "linux-tools-$(uname -r)" \
  iproute2 netcat-openbsd iputils-ping

# Stable, unversioned symlinks so the Makefile's CLANG/LLVM_STRIP defaults work.
ln -sf "/usr/bin/clang-${CLANG_VERSION}"      /usr/local/bin/clang
ln -sf "/usr/bin/llvm-strip-${CLANG_VERSION}" /usr/local/bin/llvm-strip

# --- Go --------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1 || \
   [ "$(go version | grep -oE '1\.[0-9]+' | head -n1 | cut -d. -f2)" -lt "${GO_MIN_MINOR}" ]; then
  log "Installing Go ${GO_VERSION}..."
  ARCH="$(dpkg --print-architecture)" # amd64 | arm64
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
fi
export PATH="/usr/local/go/bin:${PATH}"
grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null || \
  echo 'export PATH=/usr/local/go/bin:$PATH' > /etc/profile.d/go.sh

# --- Version assertions (hard floors) -------------------------------------
log "Verifying tool versions..."
CLANG_MAJOR="$(clang --version | grep -oE 'version [0-9]+' | grep -oE '[0-9]+' | head -n1)"
[ "${CLANG_MAJOR}" -ge 15 ] || fail "clang ${CLANG_MAJOR} < 15"
GO_MINOR="$(go version | grep -oE '1\.[0-9]+' | head -n1 | cut -d. -f2)"
[ "${GO_MINOR}" -ge "${GO_MIN_MINOR}" ] || fail "go 1.${GO_MINOR} < 1.${GO_MIN_MINOR}"
command -v bpftool >/dev/null 2>&1 || fail "bpftool missing (linux-tools-$(uname -r))"
log "clang ${CLANG_MAJOR}, go 1.${GO_MINOR}, $(bpftool version | head -n1) OK"

# --- BTF + vmlinux.h -------------------------------------------------------
[ -f /sys/kernel/btf/vmlinux ] || fail "No kernel BTF (CONFIG_DEBUG_INFO_BTF=y required)."
if [ -d "${REPO_ROOT}/bpf/include" ]; then
  log "Generating ${VMLINUX_H} from kernel BTF..."
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_H}"
else
  log "Repo not mounted at ${REPO_ROOT}; skipping vmlinux.h generation (run 'make vmlinux' later)."
fi

# --- bpffs mount (needed for pinning during tests) --------------------------
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

log "Provisioning complete. Build with:  make ebpf && make build"
