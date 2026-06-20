# Active Ticket

ID: MER-71

Title: A-2 — agent netlink veth lifecycle (RTMGRP_LINK watcher + reconcile-before-subscribe)

Objective:
Make the agent auto-manage TC program attachment over the veth lifecycle: a
netlink `RTMGRP_LINK` watcher that attaches `tc_ingress`/`tc_egress` when a pod
veth appears and detaches/cleans up when it goes away — with a **full interface
reconcile before subscribing** so events missed while the agent was down are not
lost (ARCHITECTURE lifecycle FSM: INTERFACE_RECONCILE before netlink subscribe).
This is the A-2 lane head and a Phase-3 exit criterion (ROADMAP week 5–6: every
pod veth attached within 100 ms, no leaked attachments). The A-3 lane (ADS→kernel,
MER-73) is already green; this completes the agent's self-management.

Stay in scope: `internal/agent/linkwatch` + its wiring into the supervisor + tests.
Reuse the existing `internal/agent/attach` managers (MER-57) and `bpfobj` loaders —
do NOT re-implement attach or import `bpf/` outside `bpfobj` (depguard
`wire-bpf-bridge`). Do NOT touch the eBPF programs, the frozen schema, the ADS
path, or start PKI (MER-74/75).

Dependencies:
- MER-57 (attach managers) ✅, the Phase-1 agent stub / bpfobj ✅. `vishvananda/netlink`
  (already a dep). No new deps.
- Runtime: Linux + root + netns/veth → **Lima 5.15, ISOLATED window** (netlink +
  veth churn; the dual-runner collision corrupts shared Lima runs — run ONE runner).
- depguard: `internal/agent/linkwatch` imports `attach`/`bpfobj`/`netlink`, never `bpf/`.

Acceptance Criteria:
1. `internal/agent/linkwatch`: a watcher that (a) on start performs a **full
   interface reconcile** — scan existing links, attach TC to the pods' host-side
   veths — **before** subscribing to `RTMGRP_LINK` (closes the missed-event race);
   (b) on `RTM_NEWLINK` for a matching veth, attaches (idempotent); (c) on
   `RTM_DELLINK`, detaches/cleans up; (d) survives `ENOBUFS` by resubscribing +
   full reconcile (state, not events, is truth — ARCHITECTURE failure matrix).
2. Wired into `internal/agent/supervisor` (the composition root) behind the
   existing agent lifecycle; attach uses the MER-57 `attach` managers.
3. **A-2 gate** `internal/.../linkwatch_test.go` (or `test/integration/`): create/
   destroy netns+veth in a loop; assert **every veth gets its TC programs within
   100 ms** and **no leaked attachments/qdiscs** after teardown. Arm the manifest
   row `TestVethAttachLifecycleGate_MER71` (per PHASE3_GATES) — `armed=yes`, 0 skips.
4. depguard clean (no `bpf/` from `linkwatch`); idempotent attach/detach; no
   goroutine leak on shutdown (clean stop of the watch loop).
5. `go build ./...` / `go vet ./...` clean; `go test -race ./internal/agent/...`
   compiles/green on host; `make test-integration` green on Lima (isolated);
   `make check-gate-skips` 0 skips across the now-10 armed gates; `go mod tidy` no diff.
6. After commit, `git status` clean; `make check-commits` passes (MER-71 ref).

Files Expected To Change:
- internal/agent/linkwatch/*.go        (RTMGRP_LINK watcher + reconcile-before-subscribe)
- internal/agent/supervisor/*.go        (wire the watcher into the lifecycle)
- internal/agent/linkwatch/*_test.go OR test/integration/linkwatch_test.go (A-2 gate)
- test/gates/manifest.txt                (arm TestVethAttachLifecycleGate_MER71)

Required Tests:
- `limactl shell meridian -- make test-integration` (isolated) → veth attach <100 ms, no leaks
- `limactl shell meridian -- make check-gate-skips`            → 0 skips across 10 armed gates
- `go build ./...` / `go vet ./...` / `go test -race ./internal/agent/...` → clean
- `make check-commits`                                        → MER-71 commit-linkage satisfied

Commit Message:
feat(agent): MER-71 A-2 netlink veth lifecycle — reconcile-before-subscribe + auto TC attach/detach
