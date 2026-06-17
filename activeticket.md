# Active Ticket

ID: MER-58

Title: bpfobj loader — re-open pinned sockhash on restart (pin reuse, not recreate) + T2 restart test

Objective:
Make the agent survive a restart without dropping live SOCKMAP redirect state. On
(re)start the `bpfobj` loader must **re-open the existing pinned `sockhash`** by its
bpffs pin — reusing it, not recreating it — so socket entries that `sock_ops`
inserted for established eligible flows persist across an agent restart (the
datapath deliberately leaves pins in place on shutdown, ARCHITECTURE lifecycle).
This is the LAST open Phase-2 ticket (Agent-lane robustness); it closes Phase 2.

Stay in scope: the `bpfobj` loader's sockhash open/reopen path and a T2 restart
test. Do NOT change the eBPF programs, the frozen ADR-0004 schema, the agent
attach managers (MER-57), or the control plane. The primary `LoadCounter`/
`LoadTcIngress` owns the schema-sentinel reconcile (D20) — the sockhash reopen must
not duplicate or fight that.

Dependencies:
- MER-47 (`sockhash` map) CLOSED `70c52ad`; MER-57 (`LoadSockOps`/`LoadSkMsg`
  secondary loaders + attach managers) CLOSED `014bc2e`. The reopen builds on those.
- Runtime: Linux + root + 5.15 (bpffs pins). **Verify on the Lima `meridian` VM.**
  ⚠️ MER-68 proved the dual-loop collision CORRUPTS Lima runs — **verify in an
  ISOLATED window**: instrument competing-process detection (as MER-68 did) and
  only trust a clean-window result (`GOMODCACHE=/Users/joshuawu/go/pkg/mod
  GOFLAGS=-mod=mod GOPROXY=off`, VM has no network).
- depguard `wire-bpf-bridge`: `bpfobj` is the sole `bpf/` opener — keep the load
  there; tests may use the bpftest harness.

Acceptance Criteria:
1. `internal/agent/bpfobj/loader_linux.go`: the sockhash load path uses
   **pin-or-reuse** semantics — if the `sockhash` pin already exists at the bpffs
   path, the loader RE-OPENS it (e.g. `ebpf.LoadPinnedMap` / `LoadPinOptions`)
   rather than creating a fresh map; if absent, it creates and pins it. Idempotent:
   a second `LoadSockOps`/`LoadSkMsg` against an existing pin reuses the SAME map
   (same entries), it does not clear or replace it.
2. `internal/agent/bpfobj/loader_test.go` (T2, build tag `bpf`): a **restart test**
   — load the sockhash, insert a known `sock_key`→value entry, then simulate an
   agent restart by closing the loader's handles and **re-loading via a fresh
   loader**; assert the inserted entry is **still present** (pin re-opened, not
   recreated). A complementary assertion: the re-opened map has the same map ID /
   info (same kernel object), not a new one. Must not `t.Skip` under root on 5.15.
3. ADR/architecture compliance: no change to the frozen schema; the reopen reuses
   the D18 `sockhash` shape; the schema-sentinel reconcile stays owned by the
   primary loader (D20) — sockhash reopen does not re-run it.
4. `go build ./...` / `go vet ./...` clean; `make test-bpf` green on Lima
   (including the new restart test); `go mod tidy` no diff; depguard clean.
5. After commit, `git status` is clean; `make check-commits` passes (MER-58 ref).

Files Expected To Change:
- internal/agent/bpfobj/loader_linux.go    (sockhash pin-or-reuse on (re)load)
- internal/agent/bpfobj/loader_test.go     (T2 restart test: entry survives reload)

Required Tests:
- `make test-bpf` (Lima 5.15, ISOLATED window) → restart test green; sockhash entry survives reload; 0 skips
- `go build ./...` / `go vet ./...`          → clean
- `go mod tidy`                              → no diff
- `make check-commits`                       → MER-58 commit-linkage satisfied

Commit Message:
feat(agent): MER-58 bpfobj re-open pinned sockhash on restart — entries survive agent restart
