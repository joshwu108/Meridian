# Meridian Backlog — Generated Tickets

Living ledger maintained by the **Backlog Manager**. Planned tickets MER-1 … MER-34
live in `docs/PHASE0_TICKETS.md` and `docs/PHASE1_TICKETS.md`; Phase-2 tickets
MER-47 … MER-59 live in `docs/PHASE2_TICKETS.md`. **This file lists only open
backlog tickets (MER-35+) that are not yet implemented.**

Completed backlog tickets (MER-35, MER-36, MER-37, MER-38, MER-39, MER-40,
MER-41, MER-42, MER-44, MER-45, MER-46, MER-60, MER-67, MER-68) are removed from
this file; see git history and `docs/PHASE0_REVIEW.md` for sign-off and closure
SHAs. MER-68 closed `1b5bdf3` (deterministic `check-gate-skips` — reap between
gates; 10/10 green on Lima 5.15). MER-67 closed `9d1790a` (ARCHITECTURE D21 — ADS
server decision; interim xDS encoding flagged CC-2-pending).

Next free ID = **MER-70**.

---

## Open backlog tickets

### MER-69 — Phase-3 planning: decompose A-2 / A-3 / PKI-1/2 into tickets + gates + CC-2 ADR

- **ID:** MER-69
- **TITLE:** Plan Phase 3 (agent netlink lifecycle, ADS client + translation, CA/bootstrap) — mirror the MER-46 Phase-2 planning artifact
- **PRIORITY:** P2 / MEDIUM — **the forward critical-path enabler.** Phase 2 EXIT (MER-59) is green, so Phase 3 is unblocked; it has **no tickets yet**. Like MER-46 (Phase-2 planning), this has no dependency and may land in parallel with the last Phase-2 item (MER-58).
- **ESTIMATE:** 2–3h
- **BLOCKS:** all Phase-3 implementation (A-2/A-3/PKI) — they need specced tickets + gate definitions first.
- **DEPENDENCIES:** none (planning only; MER-59 green already unblocks Phase 3). Planning artifacts are not Phase-3 *implementation*, so they may land before MER-58 closes.
- **SCOPE (per ROADMAP week 5–6, PRD phase 3):**
  - **A-2** — agent netlink lifecycle (veth scan-before-subscribe, INTERFACE_RECONCILE, link watch).
  - **A-3** — ADS client + xDS→`CommitPlan` translation (consumes the MER-54 server; replaces the MER-55 stub on the agent side; the interim JSON-in-BytesValue encoding is **CC-2-pending**, D21).
  - **PKI-1/2** — CA primitives + node bootstrap credential (CC-4).
  - **CC-2** — the compiled-policy + xDS resource **wire-contract ADR** (ROADMAP: "freeze before Phase 3 completes"; supersedes the MER-54 interim encoding flagged in D21/MER-67).
- **ACCEPTANCE CRITERIA:**
  1. `docs/PHASE3_PLAN.md`, `docs/PHASE3_TICKETS.md`, `docs/PHASE3_GATES.md` created (mirroring the Phase-2 set), decomposing A-2 / A-3 / PKI-1/2 into ticket-sized units with dependencies + a dependency graph.
  2. Phase-3 **exit gate** defined: ROADMAP week-5/6 criterion **"REST → kernel map < 500 ms measured end-to-end"** (the agent A-3 translation lands real policy in the kernel), plus the A-2/A-3 entry gates named in PHASE2_GATES.
  3. The **CC-2 wire-contract ADR** is scheduled as a Phase-3 deliverable and cross-referenced to D21 / MER-67 (interim encoding to be superseded).
  4. ROADMAP "Phase entry gates" table updated so Phase 2→3 reflects MER-59 green; tickets reserved from MER-70+.
  5. No production code; `make check-commits` passes (MER-69 ref); `git status` clean.

---

_(MER-58 — the last open Phase-2 ticket — is tracked in the table below.)_

---

## Open work tracked elsewhere

These are **not** duplicated here; see the phase ticket files:

| IDs | Where | Status (summary) |
|-----|-------|----------------|
| MER-15, MER-18, MER-19, MER-21, MER-24, MER-29, MER-32, MER-34 | `docs/PHASE1_TICKETS.md` | **Phase-1 COMPLETE & committed.** MER-15 `f70dbb5`, MER-18 `9caa828`, MER-19 `bddc72c`, MER-21 `80de7c8`, MER-24 `4ae654e`, MER-29 `fbfc00d`, MER-32 `36c0c5a`, MER-34 `a4b369d`/`31409c5`. P1.3 live-path fix (MER-66) landed `630f616` — all five gates green at HEAD, 0 skips. |
| MER-66 | this file | **CLOSED `630f616`** — P1.3 green on live two-node TCP connect; verified on Lima 5.15. |
| MER-47 | `docs/PHASE2_TICKETS.md` | **CLOSED `70c52ad`** — Phase-2 contract: `sockhash` map + `sock_ops`/`sk_msg` no-op skeletons, ARCHITECTURE D18. |
| MER-48 | `docs/PHASE2_TICKETS.md` | **CLOSED `77540ce`** — gated `sock_ops` SOCKHASH population (CC-5); `meridian_helpers.h` + D19. |
| MER-49 | `docs/PHASE2_TICKETS.md` | **CLOSED `d0125c1`** — P2.1-N permanent SOCKMAP-negative gate armed (CC-5/eBPF R2); 7 armed gates, 0 skips. CC-5 locked in CI. |
| MER-50 | `docs/PHASE2_TICKETS.md` | **CLOSED `c699887`** — `sk_msg` SOCKHASH redirect (`bpf_msg_redirect_hash`+`BPF_F_INGRESS`) + SK_PASS fall-through; smoke proves redirect-on-hit / fall-through-on-miss. SOCKHASH write+read path complete. |
| MER-57 | `docs/PHASE2_TICKETS.md` | **CLOSED `014bc2e`** — agent cgroup `sock_ops` + sockhash `sk_msg` attach (`CgroupSockOpsManager`/`SkMsgSockhashManager`, `--cgroup` opt-in), `bpfobj` secondary loaders, ARCHITECTURE D20; depguard-clean; production-path smoke green. |
| MER-51 | `docs/PHASE2_TICKETS.md` | **CLOSED `f7642c9`** — P2.2 gate armed/green: 1 MiB byte-exact over redirect + denied-never-redirected; **8 armed gates, 0 skips**. eBPF SOCKMAP lane (47–51,57) COMPLETE; CC-5 locked static (49) + runtime (51). |
| MER-53 | `docs/PHASE2_TICKETS.md` | **CLOSED `849f4a6`** — CP-1: in-memory `control.Store` (Watch seam) + monotonic identity registry (CC-3) + fail-closed REST skeleton + `meridian-control --listen`. `go test -race ./internal/control/...` green incl. CP-2; depguard clean. |
| MER-52 | `docs/PHASE2_TICKETS.md` | **CLOSED `17bc526`** — P2.2-BENCH (`e2e` tag, nightly, not a PR gate). Ran on Lima 5.15.0-179: **honest "no win" for short flows** — p50 within noise, p99 ~+280% regression, redirect engaged (+4400). SOCKMAP value is bulk-transfer correctness (MER-51), not small-flow latency. Result committed; `make test-e2e` added. |
| MER-59 | `docs/PHASE2_TICKETS.md` | **CLOSED `d8c7612` (+ MER-68 `1b5bdf3` finalizes).** Phase-2 EXIT: docs reconciled (CP-3 green, bench no-win recorded honestly, Phase-3 entry rule). The `check-gate-skips` flake that made the exit provisional is **RESOLVED by MER-68** — now deterministic (10/10 green on Lima 5.15). **Phase 2 is COMPLETE.** Remaining: CI confirmation on branch push (commits not yet on `origin`). |
| MER-68 | (closed) | **CLOSED `1b5bdf3`** — deterministic `check-gate-skips`: runs each package's armed gates in ONE `go test -parallel 1` process (like the canonical `make test-bpf`/`test-integration`), so each test's `t.Cleanup` reaps before the next — NOT a per-gate reap (a `-run`-filtered per-gate subset measured 0–8/10 flaky). Fail-closed classifier preserved (unit-tested); 10/10 green on Lima 5.15. Only residual flake = a *second* gate runner sharing the VM (dual-loop) → run one runner per machine. |
| MER-58 | `docs/PHASE2_TICKETS.md` | **ACTIVE** — the LAST open Phase-2 ticket. Agent `bpfobj` sockhash re-open on restart (pin reuse, not recreate) + T2 restart test proving sockhash entries survive (dep MER-47/57 ✅). Lima T2 — verify in an ISOLATED window (collision corrupts Lima). |
| MER-54 | `docs/PHASE2_TICKETS.md` | **CLOSED `0ff966d`** — ADS server: per-(stream, type_url) version/nonce state machine (ACK advances, NACK holds last-known-good per CC-5, stale ignored), `StreamAggregatedResources` + `Store.Watch()`-driven ordered re-push (CDS→EDS, LDS→RDS). Reuses go-control-plane xDS wire types + grpc; own thin handler. bufconn + table tests green; depguard clean; `go mod tidy` stable. |
| MER-55 | `docs/PHASE2_TICKETS.md` | **CLOSED `fe453b5`** — ADS agent stub (`StubAgent`): subscribes over loopback gRPC, decodes the Cluster-channel `BytesValue`→JSON `[]wire.PolicyRule` contract, ACKs on success / NACKs on contract violation (version reverted, config not adopted), concurrency-safe `Snapshot()`, reconnect via fresh `Run`. bufconn + decode-table tests green (`-race`); depguard clean. |
| MER-56 | `docs/PHASE2_TICKETS.md` | **CLOSED `2898a75`** — **CP-3 GATE** armed/green: ADS conformance (initial/add/delete/NACK-recovery/stale-nonce-ignore/reconnect) + REST→stub propagation measured ~1.3 ms (<500 ms budget). Manifest `armed=yes` → **9 armed gates, 0 skips**. Seed fixture committed. |
| MER-67 | this file | **CLOSED `9d1790a`** — ARCHITECTURE D21 added to the decision-log table (ADS server: grpc/go-control-plane dep, version/nonce state machine, Watch-driven ordered push, interim JSON-in-BytesValue encoding flagged superseded-by-CC-2). Prose pointer reconciled to a single source of truth. Pure-docs. |

---

<!-- Future Backlog Manager runs append new dated batches below this line. -->

## Batch 2026-06-15d — TPM/Auditor run (HEAD 849f4a6)

Findings: **MER-53 landed at `849f4a6`** — CP-1 control-plane core: `control.Store`
extended with a coalescing `Watch()` seam (`internal/control/doc.go`); in-memory
`store.Memory` (concurrency-safe, immutable value-copy snapshots, Watch teardown
closes under the write lock so a send never races a close); `identity.Registry`
(CC-3 monotonic uint32 allocator — ID 0 never handed out, idempotent by name, no
reuse across Release); fail-closed `rest.Server` (`DisallowUnknownFields` +
trailing-data rejection, 4xx structured envelope, server-side ID allocation, Go
1.22 method-routed mux → auto-405); `meridian-control --listen` with graceful
SIGINT/SIGTERM shutdown. `go test -race ./internal/control/...` green (incl. CP-2
conformance); gofmt/vet clean; depguard `control-no-dataplane` satisfied
(`pkg/wire` + stdlib + `internal/control` only). The **eBPF SOCKMAP lane and CP-1
are both complete**; the critical path to MER-59 now runs MER-54 → MER-55 →
MER-56 (CP-3 gate).

No new tickets: MER-54 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-54 — ADS server (version/nonce state machine +
ordered push)**, the next critical-path blocker and sole consumer of the MER-53
`Watch()` seam. `activeticket.md` rewritten to MER-54. Note for the implementer:
per the research-and-reuse rule, evaluate `github.com/envoyproxy/go-control-plane`
before hand-rolling the xDS state machine; depguard still forbids `bpf/`/agent
imports from `internal/control/ads`.

## Batch 2026-06-13 — Backlog Manager run (HEAD 36c0c5a)

Findings: the entire Phase-1 **exit** closure (MER-21 P1.3 arming, MER-34
ADR-0004 freeze, gate evidence) exists **only in the working tree** — 26 files
modified + 2 untracked, 0 commits. At HEAD `36c0c5a`, `manifest.txt` still has
P1.3 `armed=no` and ADR-0004 is the thin reservation, so the Phase-2 entry gate
("MER-34 green") **cannot be satisfied against committed history**. This is the
same "critical state stranded uncommitted" pattern the TPM has flagged for
multiple cycles.

---

### MER-61 — Persist the Phase-1 exit closure (commit the uncommitted tree)

- **ID:** MER-61
- **TITLE:** Commit the Phase-1 exit working tree (MER-20/21 Geneve, MER-34 ADR-0004 freeze, gate arming, docs)
- **PRIORITY:** P0 / CRITICAL (release blocker)
- **ESTIMATE:** 1–2h
- **BLOCKS:** Phase-2 entry (MER-47 … MER-59 — all gated on "MER-34 green"); any CI run that must verify gates against HEAD
- **DEPENDENCIES:** none (work already authored; this is persistence/hygiene)
- **ACCEPTANCE CRITERIA:**
  1. The working-tree changes that constitute Phase-1 exit are committed in coherent, ticket-referenced conventional commits (e.g. `feat(ebpf): MER-21 …`, `docs(adr): MER-34 …`) — no big-bang blob, per the MER-45 commit-linkage rule.
  2. After commit, `git status` is clean (no stranded modified/untracked files that belong to MER-21/MER-34).
  3. `test/gates/manifest.txt` at HEAD shows P1.3 (MER-21) `armed=yes`; ADR-0004 at HEAD is `Status: Accepted`.
  4. `docs/PHASE1_TICKETS.md` "complete (MER-34 exit)" claim is true against committed HEAD, not just the working tree.

### MER-62 — Resolve untracked `test/bpf/loadsync.go` (commit-and-wire or remove)

- **ID:** MER-62
- **TITLE:** Untracked `test/bpf/loadsync.go` — commit and reference it, or delete it
- **PRIORITY:** P1 / HIGH
- **ESTIMATE:** 1h
- **BLOCKS:** reproducibility of the bpf gate suite (MER-18/MER-21) on a clean checkout
- **DEPENDENCIES:** MER-61 (commit batch)
- **ACCEPTANCE CRITERIA:**
  1. Determine whether `loadsync.go` is required by the (currently uncommitted) bpf gate tests; it is referenced by **no committed Go file** today.
  2. If required: commit it and confirm `go test ./test/bpf/...` (Linux) compiles and uses it; if dead: remove it.
  3. No untracked `.go` files remain under `test/` after the resolution.

### MER-63 — Committed CI evidence that all five Phase-1 gates pass at HEAD

- **ID:** MER-63
- **TITLE:** Capture green-at-HEAD CI evidence for P1.1/P1.2/P1.3/CP-2/O-2 (replace working-tree-only log)
- **PRIORITY:** P1 / HIGH
- **ESTIMATE:** 2h
- **BLOCKS:** legitimate declaration of MER-34 EXIT as green; Phase-2 entry confidence
- **DEPENDENCIES:** MER-61
- **ACCEPTANCE CRITERIA:**
  1. `docs/PHASE1_GATE_EVIDENCE.log` is committed (currently untracked) and reflects the committed SHA, not a dirty tree.
  2. A CI run on the 5.15 target at committed HEAD shows all five gates green with `make check-gate-skips` reporting **0 skips** (MER-44 skip-integrity rule); CI run link recorded in `docs/PHASE1_GATES.md`.
  3. `docs/PHASE1_GATES.md` "Gate status" table cites the committed evidence, not the working tree.

### MER-64 — Dedicated ADR for SOCKMAP redirect architecture (CC-5, top-risk #2)

- **ID:** MER-64
- **TITLE:** Author ADR-0007 — SOCKHASH/sk_msg redirect + verdict-gated insertion (CC-5)
- **PRIORITY:** P2 / MEDIUM
- **ESTIMATE:** 2–3h
- **BLOCKS:** MER-47/MER-48/MER-49 design clarity (currently only an ARCHITECTURE decision-log entry D18–D20)
- **DEPENDENCIES:** MER-34 (Phase-1 exit; ROADMAP defers Phase-2 design until exit)
- **ACCEPTANCE CRITERIA:**
  1. New `docs/adr/0007-sockmap-redirect.md` records the SOCKHASH map shape, the `sock_ops` gated-insertion rule (insert **only** when verdict has `SOCKMAP_ELIGIBLE`), the `sk_msg` redirect/fall-through contract, and the rejected alternatives — closing the ROADMAP note that each cross-cutting decision (CC-5) "warrants an ADR."
  2. ADR cross-references the MER-49 permanent SOCKMAP-negative test as the enforcement of its invariant (eBPF R2 / mTLS-bypass mitigation).
  3. `docs/adr/README.md` index updated; numbering gap check passes.

## Batch 2026-06-13b — Backlog Manager run (HEAD 95ed2bb)

Findings: Phase-1 **exit is fully persisted and committed** since the prior batch —
MER-21 (`80de7c8`), MER-34 ADR-0004 + reconciliation (`a4b369d`), MER-27 policy.yaml
(`c31d03f`, the long-standing 6-cycle blocker), gate evidence log (`31409c5`), and
MER-61 closure (`95ed2bb`). `loadsync.go` is committed with a correct `//go:build bpf`
tag. CI (`ci.yml`) runs the privileged bpf+integration gate suites + `check-gate-skips`
on ubuntu-22.04 per-PR, so gate-green is a genuine CI signal. Prior-batch MER-61/62/63
are effectively retired by these commits; **MER-64 (ADR-0007) remains open and is now
unblocked**. One new documentation gap surfaced: the ledger table below is stale now
that Phase 1 is complete and Phase 2 is unblocked.

---

### MER-65 — Reconcile `tickets.md` ledger: Phase-1 complete, Phase-2 unblocked

- **ID:** MER-65
- **TITLE:** Update the "Open work tracked elsewhere" table — mark Phase-1 set complete, MER-47…59 unblocked
- **PRIORITY:** P3 / LOW (documentation hygiene)
- **ESTIMATE:** 0.5h
- **BLOCKS:** ledger accuracy for future Backlog Manager runs (avoids re-flagging done work)
- **DEPENDENCIES:** none (MER-34 already green at HEAD)
- **ACCEPTANCE CRITERIA:**
  1. The `tickets.md` row "MER-15, MER-18, MER-19, MER-21, MER-24, MER-29, MER-32, MER-34 … Phase-1 gates and remaining deliverables" is updated to reflect Phase-1 **complete** (or the IDs moved to the completed-list note like MER-35…MER-60), citing the closing SHAs.
  2. The "MER-47 … MER-59 … Blocked on MER-34 (Phase-1 exit)" status is changed to **unblocked / ready** now that MER-34 is committed-green.
  3. No open backlog ticket (MER-61…65) is altered; only the stale pointer/summary rows are corrected.

## Batch 2026-06-13c — Backlog Manager run (HEAD 2cbd04c)

Findings: MER-62 (`1f465c9`) and MER-64 ADR-0007 (`8dd56f2`) landed — both closed.
**But a P0 gate-integrity failure surfaced:** commit `2cbd04c` ("fix(gates): MER-21
Geneve live-path egress insert and TLV precedence") records in its body that **"P1.3
still red on live TCP connect."** P1.3 (MER-21) is `armed=yes` in `test/gates/manifest.txt`
and was cited as green by MER-34 EXIT — so an armed merge-blocker gate is actually RED,
violating the MER-44 skip-integrity rule and undermining the Phase-1 exit / Phase-2
entry claim. An in-flight fix (egress `bpf_skb_adjust_room` ENCAP_L2 flag, `pull_data`
placement, pre-attach neighbor resolution) sits uncommitted in `bpf/tc_egress.c` +
`test/integration/geneve_test.go`.

---

### MER-66 — P1.3 gate RED on live TCP connect: fix Geneve egress insert + restore EXIT integrity

- **ID:** MER-66
- **TITLE:** Make the MER-21 Geneve two-node gate green on the **live TCP connect** path (not just prog_test_run)
- **PRIORITY:** P0 / CRITICAL (armed merge-blocker gate is red; MER-44 violation)
- **ESTIMATE:** 4h
- **BLOCKS:** truthful MER-34 EXIT (Phase-1 exit); Phase-2 entry (MER-47 … MER-59); any merge relying on "all five Phase-1 gates green"
- **DEPENDENCIES:** none (regression on landed MER-20/MER-21 work)
- **ACCEPTANCE CRITERIA:**
  1. `TestGeneveIngressIdentityPolicyGate_MER21` passes on the **live two-node TCP connect** path on the 5.15 CI target (ubuntu-22.04, `make test-integration`) — allow-case connects, deny-case times out — not only on synthetic `prog_test_run`.
  2. The in-flight egress fix (`bpf/tc_egress.c` `insert_inner_tlv_room` flags / `pull_data` placement; the test's pre-attach neighbor-resolution step) is committed with regenerated `tcegress_bpfel.o`; `git status` clean.
  3. `make check-gate-skips` reports 0 skips **and** 0 failures for the P1.3 row at HEAD; the row stays `armed=yes` only because it is genuinely green.
  4. `docs/PHASE1_GATE_EVIDENCE.log` updated with the live-connect pass; MER-34 EXIT/`docs/PHASE1_GATES.md` no longer cite P1.3 green on stale evidence.
  5. Root-cause note added (synthetic-vs-live divergence) so the gate cannot pass synthetically while failing live again.

**Resolution (2026-06-13):** implemented under this MER-66 fix. P1.3 now runs
against the live two-node TCP path with a conflicting ingress fallback identity,
so the allow case only passes when the carried Geneve TLV is decoded and
preferred. The denied case is consumed before emission on the source Geneve
egress path and times out. Validation on Lima 5.15:
`make test-bpf`, `make test-integration`, `make check-gate-skips`, and
`make check-commits` all pass.

## Batch 2026-06-13d — TPM/Auditor run (HEAD 630f616)

Findings: **MER-66 landed at `630f616`** — P1.3 (`TestGeneveIngressIdentityPolicyGate_MER21`)
is green on the live two-node TCP connect path; working tree clean. All five
Phase-1 gates pass with 0 skips on Lima 5.15 and ADR-0004 is Accepted, so
**MER-34 (Phase-1 EXIT) is genuinely green at HEAD** and the **Phase-2 entry gate
is satisfied**. No open P0/P1 integrity violations remain. The prior batch's
stale claims (P1.3 red, Phase-2 blocked, MER-66 uncommitted) were corrected in
the "Open work tracked elsewhere" table this cycle.

No new tickets generated: Phase-2 work (MER-47 … MER-59) already exists in
`docs/PHASE2_TICKETS.md`; CC-2 (compiled-policy wire-contract ADR) is not due
until Phase-3 completion. `Next free ID` stays **MER-67**.

Selected next ticket: **MER-47 — Phase 2 contract land** (Wave-0 serialization
point; blocks the entire eBPF + Agent lanes). `activeticket.md` rewritten to
MER-47.

## Batch 2026-06-13e — TPM/Auditor run (HEAD 70c52ad)

Findings: **MER-47 landed at `70c52ad`** — the implementation loop produced real
code this cycle (`sockhash` SOCKHASH map + `struct sock_key`, no-op
`sock_ops`/`sk_msg` skeletons, bpf2go bindings, ARCHITECTURE D18). Reviewed for
ADR-0007 (SOCKHASH shape exact; gated-insertion + redirect correctly deferred to
MER-48/50), ADR-0004 (frozen schema untouched, additive map), and CC-6
(single-source `sock_key`, canonical `CounterSockKey`) — **APPROVED**. All six
Phase-1 gates remain green with 0 skips; working tree clean.

No new tickets: MER-48 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-48 — sock_ops gated SOCKHASH population (CC-5 core)**,
the next critical-path blocker (MER-47 → MER-48 → MER-50 → MER-51 → MER-59) and
the bypass point for ROADMAP Top-risk #2. It unblocks the MER-49 permanent
negative gate and MER-50 redirect. `activeticket.md` holds the MER-48 spec.

## Batch 2026-06-13f — TPM/Auditor run (HEAD 77540ce)

Findings: **MER-48 landed at `77540ce`** — gated `sock_ops` SOCKHASH population
(CC-5), shared `meridian_helpers.h` (ARCHITECTURE D19), and a cgroup-attach smoke
proving eligible-present / DENY-absent on a real loopback connect. Reviewed for
ADR-0007 (insert iff ALLOW+SOCKMAP_ELIGIBLE; fail-closed otherwise), ADR-0003
byte order, ADR-0004 (frozen schema untouched) — **APPROVED**. All six Phase-1
gates green, 0 skips.

No new tickets: MER-49 … MER-59 already exist in `docs/PHASE2_TICKETS.md`;
MER-22 (compiler-side CC-5 rejection) confirmed landed in Phase 1. `Next free ID`
stays **MER-67**.

Selected next ticket: **MER-49 — P2.1-N permanent SOCKMAP-negative gate**
(CC-5 / eBPF R2). Chosen over the parallel critical-path MER-50 (sk_msg redirect)
because MER-48 made the SOCKHASH write live with NO armed CI guard; ADR-0007
designates MER-49 as the permanent enforcement test, and the redirect consumer
must not land before the bypass invariant is locked in CI. `activeticket.md`
rewritten to MER-49.

## Batch 2026-06-14a — TPM/Auditor run (HEAD d0125c1)

Findings: **MER-49 landed at `d0125c1`** — P2.1-N permanent SOCKMAP-negative gate
is armed (`armed=yes`) and green: DENY / L7-required / mTLS-required / REDIRECT /
ALLOW-without-flag all proven absent from `sockhash`, eligible ALLOW present, on a
real loopback connect. `make check-gate-skips` now reports 0 skips across all
SEVEN armed gates. The CC-5 invariant (ROADMAP top-risk #2 / eBPF R2) is locked in
CI. Reviewed — test-only, reuses the MER-48 harness, no production code touched —
**APPROVED**.

No new tickets: MER-50 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-50 — `sk_msg` SOCKHASH redirect + SK_PASS
fall-through** (ADR-0007), the next critical-path blocker (MER-50 → MER-51 →
MER-59). It is the SOCKHASH consumer and is now safe to land because MER-49 armed
the gate guaranteeing only eligible sockets are ever inserted. Note for the
implementer (corrects the plan text): SOCKHASH redirect uses
`bpf_msg_redirect_hash`, not `bpf_msg_redirect_map`; `sk_msg` has no SK_REDIRECT
verdict. `activeticket.md` rewritten to MER-50.

## Batch 2026-06-15a — TPM/Auditor run (HEAD c699887)

Findings: **MER-50 landed at `c699887`** — `sk_msg` SOCKHASH redirect fast path:
hit → `bpf_msg_redirect_hash` + `BPF_F_INGRESS`, miss → `SK_PASS` fall-through,
redirect counter bounded per D13. Solved the verifier's unreleasable-socket-ref
trap (arm `sk_redir` via the helper, always return SK_PASS) and validated the
`remote_port >> 16` byte order via the redirect counter. Reviewed for ADR-0007
(sole reader, fall-through) — **APPROVED**. SOCKHASH write (sock_ops) + read
(sk_msg) path is now complete; 7 armed gates remain green, 0 skips.

No new tickets: MER-51 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-57 — Agent cgroup + SOCKHASH attach path**. The
critical-path P2.2 gate (MER-51) is now blocked ONLY on MER-57 (MER-50 done) —
its AC requires the agent (not the test harness) to attach sock_ops/sk_msg.
MER-57 unblocks MER-51 + MER-58. Outranks the parallel Platform lane (MER-53).
Note: ARCHITECTURE D19 is taken (MER-48 helper boundary) — MER-57 records D20.
`activeticket.md` holds the MER-57 spec.

## Batch 2026-06-15b — TPM/Auditor run (HEAD 014bc2e)

Findings: **MER-57 landed at `014bc2e`** — the production agent now attaches the
SOCKMAP fast path: `CgroupSockOpsManager` (sock_ops → cgroup v2) +
`SkMsgSockhashManager` (sk_msg → sockhash fd), behind `meridian-agent --cgroup`
(disabled by default). Loaders live in `bpfobj` (sole `bpf/` opener) so the
depguard wire-bpf-bridge boundary holds; attach managers take `*ebpf.Program`,
never `bpf/`. ARCHITECTURE D20 recorded. Reviewed — idempotent attach/detach,
production-path smoke proves a real redirect — **APPROVED**. 7 armed gates green,
0 skips; `make ebpf` clean (Go+docs only).

No new tickets: MER-51 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-51 — P2.2 GATE (SOCKMAP byte integrity +
denied-never-redirected)**. Next critical-path item AND a gate; now unblocked
(MER-50 ✅, MER-57 ✅). It is the RUNTIME half of CC-5 / Top-risk #2 (MER-49 is the
static half): ≥1 MiB byte-exact transfer over the redirect path + DENY flows never
complete via SOCKMAP. `activeticket.md` holds the MER-51 spec. Note for the
implementer: the `bpftest` (tag `bpf`) helpers are not importable from
`test/integration` (tag `integration`) — build the suite on `test/harness` + the
production `bpfobj`/`attach` managers.

## Batch 2026-06-15c — TPM/Auditor run (HEAD f7642c9)

Findings: **MER-51 landed at `f7642c9`** — P2.2 gate armed and green: an eligible
flow transfers 1 MiB byte-for-byte (sha256) over the SOCKMAP redirect path
(METRIC_FLOWS_REDIRECTED rises) and a denied flow never redirects (counter flat)
while its bytes still flow normally. `make check-gate-skips` now reports 0 skips
across all EIGHT armed gates. With MER-49 (static) + MER-51 (runtime), the CC-5
invariant / ROADMAP Top-risk #2 is locked in CI from both sides.

**The Phase-2 eBPF SOCKMAP lane (MER-47/48/49/50/51/57) is COMPLETE.** The
critical path to the Phase-2 exit (MER-59 ← {49 ✅, 51 ✅, 56, 52}) now runs through
the Platform lane: MER-53 → MER-54 → MER-55 → MER-56 (CP-3 gate).

No new tickets: MER-52 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-53 — CP-1 (memory store + identity registry + REST
skeleton)**. Head of the now-critical Platform lane and a foundation for the CP-3
gate (MER-56) that MER-59 needs. Pure-Go T1 (no Lima). Note for the implementer:
the `control.Store` interface already exists in `internal/control/doc.go` (package
`control`) — reconcile with it (don't duplicate); include a `Watch()` change-notify
seam that MER-54's ADS push will consume. `activeticket.md` holds the MER-53 spec.

## Batch 2026-06-16a — TPM/Auditor run (HEAD 0ff966d)

Findings: **MER-54 landed at `0ff966d`** — control-plane ADS server: per-(stream,
type_url) version/nonce state machine (ACK advances accepted version, NACK holds
last-known-good per CC-5, stale nonce ignored), `StreamAggregatedResources` with a
`Store.Watch()`-driven ordered re-push in canonical make-before-break order
(CDS→EDS, LDS→RDS). Reuses the go-control-plane xDS wire types (`discovery/v3`,
`pkg/resource/v3`) + grpc transport but implements its own thin handler + state
machine to keep CC-5 fail-closed explicit; policy rides the Cluster channel as a
JSON-in-`wrapperspb.BytesValue` Any (documented internal server↔stub contract,
real model deferred to CC-2). Reviewed — bufconn gRPC + pure table tests cover
ACK/NACK/stale/initial/resubscribe + ordered Watch re-push; `go test -race
./internal/control/...` 5/5 green incl MER-53 + CP-2; depguard clean; `go mod tidy`
idempotent. **APPROVED.** (Note: MER-54 was authored but left stranded uncommitted
for a full cycle by a peer loop, and its go.mod was un-tidied — both fixed before
the commit.)

No new tickets: MER-55 … MER-59 already exist in `docs/PHASE2_TICKETS.md`.
`Next free ID` stays **MER-67**.

Selected next ticket: **MER-55 — ADS agent stub (in-memory xDS client)**. The next
critical-path blocker (MER-55 → MER-56 CP-3 gate → MER-59 EXIT); the conformance
gate (MER-56) needs a stub agent to drive the server through connect → receive →
ACK → reconnect. Pure-Go T1 (no Lima). Note for the implementer: the MER-54 server
encodes policy as JSON-in-`wrapperspb.BytesValue` on the Cluster channel only — the
stub must decode that exact contract and NACK on a contract violation (e.g. wrong
type_url payload or undecodable resource). `activeticket.md` holds the MER-55 spec.

## Batch 2026-06-16b — TPM/Auditor run (HEAD fe453b5)

Findings: **MER-55 landed at `fe453b5`** — ADS agent stub (`StubAgent`): opens one
`StreamAggregatedResources`, subscribes to all types, decodes the MER-54 contract
(Cluster-channel `wrapperspb.BytesValue`→JSON `[]wire.PolicyRule`; other channels
versioned-but-empty), ACKs on success / **NACKs** on a contract violation
(error_detail set, version reverted to last-accepted, rejected config never
adopted — CC-5 mirrored client-side), exposes a concurrency-safe deep-copy
`Snapshot()`, reconnects via a fresh `Run`. Reviewed — bufconn tests cover
initial+update, reconnect-re-receives-offline-change (clean Run return = no
goroutine leak), NACK-via-fake-server, and a 7-case `decodeSnapshot` table;
`go test -race ./internal/control/...` 5/5 green incl MER-53/54/CP-2; depguard
clean; `go mod tidy` stable (no new deps). **APPROVED.**

**MER-67 (ADS D21 ADR) was generated last interval (`f25aa43`)** and is correctly
P3/LOW + off critical path — it does not block the CP-3 gate or Phase-2 exit.
`Next free ID` is now **MER-68**.

Selected next ticket: **MER-56 — CP-3 GATE (ADS conformance + <500 ms
propagation)**. Highest priority: it is BOTH the next critical-path blocker AND a
gate ticket (outranks the P3 MER-67 doc and the off-path MER-52/58 leaves). It is
the final MER-59 EXIT join dep on the Platform lane and the first end-to-end wiring
of REST (MER-53) → store → ADS server (MER-54) → stub (MER-55). Pure-Go T1 (no
Lima). `activeticket.md` rewritten to MER-56. Implementer notes: (1) drive the
MER-55 stub against the MER-54 server over bufconn through initial / add / delete /
NACK-recovery / out-of-order-nonce-ignore / reconnect; (2) the <500 ms propagation
must be measured with a polling WaitUntil, NOT time.Sleep; (3) the out-of-order
nonce sub-case may need a raw client stream (the stub always answers the latest
push) — assert the server ignores a stale nonce with no state change; (4) flip the
manifest CP-3 row `no`→`yes` and confirm `make check-gate-skips` = 0 skips across
all 9 armed gates; the conformance test must never `t.Skip` (pure Go, always runs).

## Batch 2026-06-16c — TPM/Auditor run (HEAD 2898a75)

Findings: **MER-56 landed at `2898a75`** — CP-3 GATE armed and green:
`TestADSConformanceGate_MER56` drives the MER-55 stub + raw xDS clients against the
MER-54 server through initial snapshot / policy add / policy delete / NACK recovery
(server holds last-known-good, later valid change still propagates) / stale-nonce
ignored (no state change, raw-stream asserted) / reconnect re-receives offline
changes; plus the end-to-end spine REST `POST /policies` → shared `control.Store` →
ADS server → stub `Snapshot()` measured at ~1.3 ms (<500 ms budget) via polling
`waitUntil` (not sleep). Regression seed `testdata/conformance_seed.json` committed;
manifest CP-3 flipped `armed=yes` → **9 armed gates, 0 skips**. Reviewed —
`go test -race ./internal/control/...` green incl MER-53/54/55 + CP-2; depguard
clean; tidy stable; the gate never `t.Skip`s. **APPROVED.**

**The Platform/ADS lane (MER-53→54→55→56) is COMPLETE.** Phase-2 EXIT (MER-59)
join `{49 ✅, 51 ✅, 56 ✅, 52}` now has exactly ONE open dependency: **MER-52**.
No new tickets. `Next free ID` stays **MER-68**.

Selected next ticket: **MER-52 — P2.2-BENCH (intra-node SOCKMAP latency
benchmark)**. It is the sole remaining MER-59 EXIT dependency = the critical-path
blocker for Phase-2 exit (outranks the off-path MER-58 Agent leaf and the P3
MER-67 ADS-ADR). ⚠️ Unlike MER-53…56 (pure-Go T1), MER-52 is a **T4 `e2e`-tagged**
Linux benchmark — the implementer must run it on the **Lima `meridian` VM** (5.15,
root); it is NOT a PR merge gate and arms NO manifest row. Reuse the MER-51
integrity harness (production `bpfobj`/`attach` + `test/harness`). Report honestly:
a measured win with numbers OR "no win on <kernel>" with the numbers — do not
green-wash. Commit results to `test/integration/testdata/sockmap_bench.json`.
`activeticket.md` holds the MER-52 spec.

## Batch 2026-06-16d — TPM/Auditor run (HEAD 17bc526)

Findings: **MER-52 landed at `17bc526`** — P2.2-BENCH intra-node SOCKMAP latency
benchmark (`//go:build e2e`, T4 nightly, NOT a PR gate, arms no manifest row).
Ran on the Lima `meridian` VM (kernel 5.15.0-179, n=2000) via the production attach
path (bpfobj + cgroup sock_ops + sockhash sk_msg). **Honest result: no latency win
for short connect+first-byte flows** — p50 within run-to-run noise (~±6%), a
consistent p99 regression (~+280–377%), redirect confirmed engaged
(METRIC_FLOWS_REDIRECTED +4400). Verdict requires BOTH p50 and p99 to improve for a
"win" (a p50-only gain is reported "mixed/no-win", never green-washed). Result →
`test/integration/testdata/sockmap_bench.json`; `make test-e2e` target added.
Reviewed — PR suites unaffected (e2e tag-excluded), host build/vet clean, tidy
stable, manifest unchanged (9 armed gates). **APPROVED.** Useful finding: SOCKMAP's
value is bulk-transfer correctness (MER-51), not small-flow latency on 5.15.

**Phase-2 implementation is COMPLETE.** All MER-59 EXIT joins {49 ✅, 51 ✅, 56 ✅,
52 ✅} are satisfied. No new tickets. `Next free ID` stays **MER-68**.

Selected next ticket: **MER-59 — Phase-2 EXIT gate** (doc reconciliation + Phase-3
entry rule). The final Phase-2 ticket — pure docs (PHASE2_GATES all-green evidence,
README Phase-2-complete, ROADMAP week-4 exit checkoff, ARCHITECTURE D18–D20 as-built
+ a pointer to the pending D21/MER-67 ADS decision, Phase-3 entry rule = MER-59
green + ADR-0004 unchanged). T1, but the implementer MUST cite a REAL Lima-5.15
green-gate run (`make test-bpf`/`test-integration`/`check-gate-skips`, 0 skips) — no
stale/asserted green. MER-58 (Agent leaf) + MER-67 (ADS D21 ADR) remain open
off-path and do NOT block Phase-2 exit. `activeticket.md` holds the MER-59 spec.

## Batch 2026-06-16e — TPM/Auditor run (HEAD 1b5bdf3)

Findings: **MER-68 landed at `1b5bdf3`** — `check-gate-skips` is now deterministic:
`checkgateskips` reaps leaked `mrdn-*` netns + `/sys/fs/bpf/meridian-test` before
each privileged (`bpf`/`integration`) gate (pure-Go gates skip the reap); the
skip/fail classifier was extracted (`classifyEvents`) and unit-tested so the reap
cannot mask a red gate (MER-44 fail-closed intact). **Verified 10/10 consecutive
green on Lima 5.15.0-179** when it is the sole gate runner. Key diagnostic note:
the verification was nearly derailed by the dual-loop collision — a *second* loop
running gate tests in the same VM made the fix look broken (9/10) until an
instrumented competing-process guard isolated a clean window; **a per-gate reap
cannot defend against a concurrent root gate-runner.** PHASE2_GATES caveat replaced
with the deterministic result. **This finalizes the MER-59 Phase-2 EXIT — Phase 2
is COMPLETE.** No production code touched.

No new tickets. Open: MER-67 (selected), MER-58. `Next free ID` stays **MER-69**.

Selected next ticket: **MER-67 — ARCHITECTURE D21 (ADS server) + interim
xDS-encoding CC-2-pending note.** With Phase 2 substantively done and all gates
green, the highest-value ready item is closing the architecture-compliance gap:
the ADS decision (gRPC/go-control-plane dep, version/nonce state machine,
Watch-driven CDS→EDS/LDS→RDS push, interim JSON-in-BytesValue encoding) is
load-bearing across MER-54/55/56 but recorded only in code comments + the pending-
D21 pointer MER-59 added. **Pure-docs (no Lima)** — deliberately chosen over MER-58
(agent restart, Lima T2) because MER-68 just proved the dual-loop collision
CORRUPTS Lima verification; MER-58 should wait until one gate runner per VM is
enforced. MER-67 formalizes the D21 pointer into a full decision-log entry,
cross-references CC-2, and flags the interim encoding as superseded-by-Phase-3.
`activeticket.md` holds the MER-67 spec. (Operator: push the branch — 40+ Phase-2
commits have NEVER hit CI.)

## Batch 2026-06-16f — TPM/Auditor run (HEAD 9d1790a)

Findings: **MER-67 landed at `9d1790a`** — ARCHITECTURE D21 now a formal
decision-log row (ADS server MER-54/55/56: grpc + go-control-plane dep per D11,
per-(stream,type_url) version/nonce handshake, `Store.Watch()`-driven
CDS→EDS/LDS→RDS push, **interim** JSON-in-`BytesValue` Cluster-channel encoding
flagged **superseded by the CC-2 wire-contract freeze (Phase 3)**). The prior prose
"Pending — D21" pointer was reconciled into a single CC-2-boundary note. Pure-docs,
no production code. **APPROVED.**

No new tickets. The "Open backlog tickets" section is now empty. `Next free ID`
stays **MER-69**.

Selected next ticket: **MER-58 — `bpfobj` sockhash re-open on restart + T2 restart
test.** It is the **LAST open Phase-2 ticket** (an Agent-lane robustness deliverable:
on agent restart the loader must RE-OPEN the pinned `sockhash` — pin reuse, not
recreate — so live SOCKMAP redirect state survives a restart). Deps MER-47/57 ✅.
Chosen because it is the only ready ticket and closes Phase 2 fully; Phase-3
planning (A-2/A-3/PKI — no PHASE3 docs exist yet) is the next major effort after it.
⚠️ **Lima T2** — the implementer MUST verify in an ISOLATED window: MER-68 proved
the dual-loop collision corrupts Lima runs, so instrument competing-process
detection (as MER-68 did) and only trust a clean-window result. `activeticket.md`
holds the MER-58 spec. (Operator: still no push — 40+ Phase-2 commits have never
hit CI; and the collision remains unresolved.)
