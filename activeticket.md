# Active Ticket

ID: MER-71

Title: A-2 — agent netlink veth lifecycle (3/N: supervisor wiring + A-2 gate) — CONTINUATION

Objective:
Finish MER-71. Parts 1/N (`2778bd9` — lifecycle orchestrator, reconcile-before-
events, attach/detach dispatch) and 2/N (`896f851` — RTNLGRP_LINK netlink
Watcher, reconcile + add/remove classify) are COMMITTED and host-green. What
remains to close the ticket:

  (a) wire the linkwatch orchestrator into `internal/agent/supervisor` (the
      composition root) behind the existing agent lifecycle — currently NO
      reference to `linkwatch` exists in `supervisor/` or `cmd/`;
  (b) ENOBUFS resilience: on netlink overrun, resubscribe + full reconcile
      (state, not events, is truth — ARCHITECTURE failure matrix) — verify it
      is implemented end-to-end through the orchestrator, add coverage if not;
  (c) the A-2 GATE test `TestVethAttachLifecycleGate_MER71`: netns+veth
      create/destroy loop; every veth gets its TC programs within 100 ms; no
      leaked attachments/qdiscs after teardown;
  (d) arm the manifest row (11 armed gates, 0 skips) and verify on Lima 5.15
      in an ISOLATED window.

Stay in scope: `internal/agent/linkwatch` + supervisor wiring + tests. Reuse
the MER-57 `attach` managers and `bpfobj` loaders — do NOT re-implement attach
or import `bpf/` outside `bpfobj` (depguard `wire-bpf-bridge`). Do NOT touch
the eBPF programs, the frozen schema, the ADS path, or start PKI (MER-74/75).

Dependencies:
- MER-57 (attach managers) ✅, bpfobj ✅, `vishvananda/netlink` ✅ (already a dep).
  Parts 1–2 of this ticket ✅ committed. No new deps.
- Runtime: Linux + root + netns/veth → **Lima 5.15, ISOLATED window** (netlink +
  veth churn; the dual-runner collision corrupts shared Lima runs — run ONE runner).
- depguard: `internal/agent/linkwatch` imports `attach`/`bpfobj`/`netlink`, never `bpf/`.

Acceptance Criteria:
1. Watcher semantics complete: (a) full interface reconcile BEFORE subscribing
   to RTMGRP_LINK ✅ (1/N–2/N, verify at wiring level); (b) RTM_NEWLINK for a
   matching veth → idempotent attach; (c) RTM_DELLINK → detach/cleanup;
   (d) ENOBUFS → resubscribe + full reconcile (add if missing).
2. Wired into `internal/agent/supervisor` behind the existing agent lifecycle;
   attach uses the MER-57 `attach` managers; clean stop of the watch loop on
   shutdown (no goroutine leak).
3. **A-2 gate** `TestVethAttachLifecycleGate_MER71` (in
   `internal/.../linkwatch_test.go` or `test/integration/`): create/destroy
   netns+veth in a loop; assert every veth attached within **100 ms** and
   **no leaked attachments/qdiscs** after teardown. Arm the manifest row
   (`armed=yes`) per PHASE3_GATES — 0 skips.
4. depguard clean (no `bpf/` from `linkwatch`); idempotent attach/detach.
5. `go build ./...` / `go vet ./...` clean; `go test -race ./internal/agent/...`
   green on host; `make test-integration` green on Lima (ISOLATED window);
   `make check-gate-skips` 0 skips across the now-11 armed gates;
   `go mod tidy` no diff.
6. After commit, `git status` clean; `make check-commits` passes (MER-71 ref).
   Push the branch — 2 MER-71 commits are not yet on origin.

Files Expected To Change:
- internal/agent/supervisor/*.go        (wire linkwatch into the lifecycle)
- internal/agent/linkwatch/*.go          (only if ENOBUFS path needs completion)
- internal/agent/linkwatch/*_test.go OR test/integration/linkwatch_test.go (A-2 gate)
- test/gates/manifest.txt                (arm TestVethAttachLifecycleGate_MER71)

Required Tests:
- `limactl shell meridian -- make test-integration` (isolated) → veth attach <100 ms, no leaks
- `limactl shell meridian -- make check-gate-skips`            → 0 skips across 11 armed gates
- `go build ./...` / `go vet ./...` / `go test -race ./internal/agent/...` → clean
- `make check-commits`                                        → MER-71 commit-linkage satisfied

Commit Message:
feat(agent): MER-71 (3/N) supervisor wiring + A-2 veth lifecycle gate — attach <100 ms, no leaks
