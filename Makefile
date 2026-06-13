# Meridian — top-level Makefile.
#
# eBPF object generation is Linux-only. Targets that touch clang/bpftool/bpffs
# detect a non-Linux host and fail with a clear message rather than a cryptic
# toolchain error (dev happens in a Lima VM on macOS).
#
# Conventions:
#   - Go module:  github.com/joshuawu/meridian
#   - bpf2go output is committed under bpf/  (no hand-written Go mirrors)
#   - One .c program per bpf2go invocation, all driven by bpf/gen.go

# ---------------------------------------------------------------------------
# Tunable toolchain variables (override on the command line, e.g. CLANG=clang-17)
# ---------------------------------------------------------------------------
CLANG        ?= clang
LLVM_STRIP   ?= llvm-strip
GO           ?= go
BPFTOOL      ?= bpftool
GOLANGCILINT ?= golangci-lint
BPF_TARGET   ?= bpfel

# Minimum toolchain versions (documented; checked by `make doctor`).
CLANG_MIN_MAJOR := 15
GO_MIN_VERSION  := 1.22

GOOS := $(shell command -v $(GO) >/dev/null 2>&1 && $(GO) env GOOS || uname | tr '[:upper:]' '[:lower:]')

# Paths.
BPF_DIR     := bpf
BPF_INCLUDE := $(BPF_DIR)/include
VMLINUX_H   := $(BPF_INCLUDE)/vmlinux.h
VMLINUX_BTF := /sys/kernel/btf/vmlinux
BIN_DIR     := bin

# bpf2go consumes these via gen.go's $BPF_CFLAGS; -Iinclude is relative to
# bpf/ because `go generate` runs in the package directory. Keep paths
# relative so no absolute build paths leak into the committed objects
# (determinism).
BPF_CFLAGS := -O2 -g -Wall -Werror -target $(BPF_TARGET) -mcpu=v3 -Iinclude -fdebug-prefix-map=$(CURDIR)=.

# Guard that aborts a Linux-only target on a non-Linux host with a clear message.
define require_linux
	@if [ "$(GOOS)" != "linux" ]; then \
		echo "ERROR: '$@' requires Linux (eBPF toolchain). Host GOOS=$(GOOS)."; \
		echo "       Run inside the Lima VM:  limactl shell meridian -- make $@"; \
		exit 1; \
	fi
endef

.DEFAULT_GOAL := help

.PHONY: help
help: ## Print this help (targets with ## comments)
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# eBPF codegen
# ---------------------------------------------------------------------------
# NOTE: counter.c is retained as a toolchain/verifier smoke artifact only; the
# production datapath verdict logic lives in tc_ingress.c (MER-17+).
.PHONY: ebpf
ebpf: ## Compile bpf/*.c and regenerate committed bpf2go Go bindings (Linux-only)
	$(require_linux)
	@test -f $(VMLINUX_H) || { echo "ERROR: $(VMLINUX_H) missing. Run 'make vmlinux' first."; exit 1; }
	CLANG=$(CLANG) STRIP=$(LLVM_STRIP) BPF_TARGET=$(BPF_TARGET) BPF_CFLAGS="$(BPF_CFLAGS)" \
		$(GO) generate ./$(BPF_DIR)/...
	@test -f $(BPF_DIR)/counter_bpfel.go || { echo "ERROR: expected generated file bpf/counter_bpfel.go was not created."; exit 1; }
	@test -f $(BPF_DIR)/counter_bpfel.o || { echo "ERROR: expected generated file bpf/counter_bpfel.o was not created."; exit 1; }
	@test -f $(BPF_DIR)/tcingress_bpfel.go || { echo "ERROR: expected generated file bpf/tcingress_bpfel.go was not created."; exit 1; }
	@test -f $(BPF_DIR)/tcingress_bpfel.o || { echo "ERROR: expected generated file bpf/tcingress_bpfel.o was not created."; exit 1; }

.PHONY: vmlinux
vmlinux: ## Regenerate bpf/include/vmlinux.h from the running kernel's BTF (Linux-only)
	$(require_linux)
	@test -f $(VMLINUX_BTF) || { echo "ERROR: $(VMLINUX_BTF) not found (CONFIG_DEBUG_INFO_BTF=y required)."; exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
	@echo "Wrote $(VMLINUX_H)"

.PHONY: verify-gen
verify-gen: ## Determinism gate: regenerate bindings and fail if the git tree changed
	$(require_linux)
	$(MAKE) ebpf
	@echo "Checking generated eBPF bindings are up to date..."
	@git diff --exit-code -- '$(BPF_DIR)/*_bpfel.go' '$(BPF_DIR)/*_bpfel.o' \
		|| { echo "ERROR: generated eBPF bindings are stale. Run 'make ebpf' and commit the result."; exit 1; }

# ---------------------------------------------------------------------------
# Go build
# ---------------------------------------------------------------------------
.PHONY: build
build: ## Build the meridian-agent binary (control/CLI binaries arrive in Phases 3/6)
	$(MAKE) build-agent

.PHONY: build-agent
build-agent: ## Build bin/meridian-agent
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/meridian-agent ./cmd/meridian-agent
	@echo "Built: $(BIN_DIR)/meridian-agent"

# ---------------------------------------------------------------------------
# Test tiers (T1 portable, T2/T3 privileged Linux)
# ---------------------------------------------------------------------------
.PHONY: test-unit
test-unit: ## T1: pure-Go unit tests; runs anywhere incl. macOS host
	$(GO) test -race -count=1 ./...

.PHONY: test-bpf
test-bpf: ## T2: bpf_prog_test_run + bpfobj loader tests (tag 'bpf'); needs root/CAP_BPF, Linux
	$(require_linux)
	$(GO) test -tags=bpf -exec sudo -count=1 ./test/bpf/... ./internal/agent/bpfobj/...

.PHONY: test-integration
test-integration: ## T3: netns integration tests (tag 'integration'); needs root, Linux
	$(require_linux)
	$(GO) test -tags=integration -exec sudo -count=1 -timeout=10m ./test/integration/...

.PHONY: check-gate-skips
check-gate-skips: ## MER-44: fail if any armed Phase-1 gate test reports skips
	$(require_linux)
	$(GO) run ./test/tools/checkgateskips -manifest test/gates/manifest.txt

.PHONY: bench
bench: ## Run Go benchmarks (bpf-tagged benches need root + Linux)
	$(GO) test -tags=bpf -exec sudo -run=^$$ -bench=. -benchmem ./...

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------
.PHONY: fmt
fmt: ## Format Go and C sources
	$(GO) fmt ./...
	@command -v clang-format >/dev/null 2>&1 \
		&& find $(BPF_DIR) \( -name '*.c' -o -name '*.h' \) ! -name vmlinux.h -print0 | xargs -0 -r clang-format -i \
		|| echo "clang-format not found; skipping C formatting"

.PHONY: lint
lint: ## Run go vet and golangci-lint (incl. depguard import rules)
	$(GO) vet ./...
	@command -v $(GOLANGCILINT) >/dev/null 2>&1 \
		&& $(GOLANGCILINT) run ./... \
		|| echo "golangci-lint not found; skipping (see https://golangci-lint.run)"

.PHONY: check-commits check-provenance-notes
check-commits: ## MER-45: verify feat/fix/refactor commits cite MER-<n> tickets
	@bash scripts/check-mer-ticket-refs.sh

check-provenance-notes: ## MER-45: verify backfilled git notes on mislabeled mega-commits
	@bash scripts/verify-provenance-notes.sh

# ---------------------------------------------------------------------------
# Environment hygiene / diagnostics
# ---------------------------------------------------------------------------
.PHONY: test-clean
test-clean: ## Reap leaked netns and bpffs pins left by aborted privileged tests
	$(require_linux)
	@echo "Reaping meridian test network namespaces..."
	@ip netns list 2>/dev/null | awk '/^mrdn-/{print $$1}' | xargs -r -n1 sudo ip netns delete || true
	@echo "Removing leftover test pins under /sys/fs/bpf/meridian-test..."
	@sudo rm -rf /sys/fs/bpf/meridian-test 2>/dev/null || true
	@echo "test-clean done."

.PHONY: doctor
doctor: ## Check kernel configs, BTF, and tool versions for eBPF development
	@echo "== Host =="
	@echo "GOOS: $(GOOS)"
	@if [ "$(GOOS)" != "linux" ]; then \
		echo "Not Linux: eBPF build/test must run in the Lima VM. Skipping kernel checks."; \
		exit 0; \
	fi
	@echo "== Tool versions =="
	@$(CLANG) --version 2>/dev/null | head -n1 || echo "clang: MISSING (need >= $(CLANG_MIN_MAJOR))"
	@$(GO) version || echo "go: MISSING (need >= $(GO_MIN_VERSION))"
	@$(BPFTOOL) version 2>/dev/null | head -n1 || echo "bpftool: MISSING (install linux-tools-$$(uname -r))"
	@echo "== Kernel =="
	@uname -r
	@echo "== BTF (CO-RE) =="
	@test -f $(VMLINUX_BTF) && echo "BTF present: $(VMLINUX_BTF)" || echo "BTF MISSING: CONFIG_DEBUG_INFO_BTF=y required"
	@echo "== Required kernel config =="
	@CFG=/boot/config-$$(uname -r); \
	 [ -f $$CFG ] || CFG=/proc/config.gz; \
	 for opt in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_NET_CLS_BPF CONFIG_NET_ACT_BPF \
	            CONFIG_BPF_JIT CONFIG_DEBUG_INFO_BTF CONFIG_BPF_EVENTS CONFIG_SOCK_CGROUP_DATA; do \
	   if zgrep -q "^$$opt=y" $$CFG 2>/dev/null || grep -q "^$$opt=y" $$CFG 2>/dev/null; then \
	     echo "  ok   $$opt"; else echo "  MISS $$opt"; fi; \
	 done
	@echo "doctor done."

.PHONY: clean
clean: ## Remove build artifacts (keeps committed generated bindings)
	rm -rf $(BIN_DIR)
	$(GO) clean -testcache 2>/dev/null || true
