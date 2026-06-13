# Meridian Backlog — Generated Tickets

Living ledger maintained by the **Backlog Manager**. Existing planned tickets
(MER-1 … MER-34) live in `docs/PHASE0_TICKETS.md` and `docs/PHASE1_TICKETS.md`
and are **never modified here**. This file only **appends new tickets** that the
existing backlog does not already track.

ID allocation continues from MER-34 (next free = MER-35).

---

## Batch 2026-06-13 (Backlog Manager run 1)

Sources reviewed: `ROADMAP.md`, `docs/adr/000{1,2,3,5}-*.md`,
`docs/PHASE0_REVIEW.md`, `docs/PHASE{0,1}_TICKETS.md`, git history
(`a159f3c`…`64148cc`), repo working tree.

Completed per git history: MER-14, 16, 20, 22, 25, 26, 27, 28, 30.
Open per plan: MER-15, 17, 18, 19, 21, 23, 24, 29, 31, 32, 33, 34.

---

### MER-35 — Phase-0 exit re-review & verification sign-off
- **ID:** MER-35
- **TITLE:** Phase-0 exit re-review & verification sign-off (close PHASE0_REVIEW F-1…F-4)
- **PRIORITY:** P0 / BLOCKER
- **ESTIMATE:** 3h
- **BLOCKS:** MER-18, MER-21, MER-24, MER-29, MER-32, MER-34 (every Phase-1 gate)
- **DEPENDENCIES:** MER-7, MER-8, MER-10 (Linux/CI gates), MER-11, MER-12, MER-13
- **ACCEPTANCE CRITERIA:**
  - `docs/PHASE0_REVIEW.md` carries a dated re-review addendum confirming F-1 (compile), F-2 (failing fixture), F-3 (agent TC attach via MER-25) are closed, each with the commit SHA that closed it.
  - Evidence captured that the four Phase-0 exit gates ran green on the 5.15 target: `make verify-gen` (deterministic), verifier-clean load, byte-correct ring decode, PERCPU counter readback — CI run links or VM logs attached.
  - A written "Phase 1 entry approved" decision recorded (the review currently reads **NOT READY**); if any gate is still red, this ticket stays open and Phase-1 merges are frozen.
  - Confirms `go.sum`, `vmlinux.h`, and generated bindings (`*_bpfel.go/.o`) are committed (F-4 prerequisites).

**Status (2026-06-13): done (`2d8fed4`)** — closing commit lands bindings + `docs/PHASE0_GATE_EVIDENCE.log`;
`docs/PHASE0_REVIEW.md` records Phase 1 entry APPROVED. Also closes **MER-60** (duplicate F-4 ticket). — Schema-sentinel stamp-time race (now unsound at v2)
- **ID:** MER-36
- **TITLE:** Make schema-sentinel stamping atomic (close review D-9)
- **PRIORITY:** P1 / HIGH
- **ESTIMATE:** 3h
- **BLOCKS:** MER-29 (restart-preserves-enforcement assertion), MER-34
- **DEPENDENCIES:** MER-14 (schema bumped to v2 — the trigger this debt was filed against)
- **ACCEPTANCE CRITERIA:**
  - A crash between map creation and sentinel stamp can no longer leave version 0 such that a newer build silently stamps over old-build maps (review D-9).
  - Stamping is part of an atomic init marker (or equivalent ordering proof); `bpfobj` opens fail closed on a partially-initialized pin set.
  - T2 regression test simulates the crash-between-create-and-stamp window and asserts fail-closed behavior on the next open.
  - Pay-down trigger ("schema version 2") is recorded as resolved in the review debt register.

### MER-37 — Resolve dual netns tooling divergence
- **ID:** MER-37
- **TITLE:** Single-source netns fixture (Go harness vs bash scripts) — close review C-4 / D-4
- **PRIORITY:** P2 / MEDIUM
- **ESTIMATE:** 2–3h
- **BLOCKS:** MER-21, MER-29 (multi-node integration reliability)
- **DEPENDENCIES:** MER-28 (two-node fixture landed — the stated pay-down trigger has passed)
- **ACCEPTANCE CRITERIA:**
  - Exactly one authoritative netns path: either `test/harness/*` shells out to `scripts/netns/*.sh`, or the scripts carry a "debug-only; harness is authoritative" banner and a test asserts they are not used in CI.
  - The already-divergent `tc qdisc add` (harness) vs `tc qdisc replace` (scripts) commands are reconciled.
  - `docs/NETNS_SCRIPTS.md` updated to state which surface is authoritative.

### MER-38 — Pin golangci-lint-action to a fixed version
- **ID:** MER-38
- **TITLE:** Make CI lint reproducible — pin `golangci-lint-action` (close review D-7)
- **PRIORITY:** P2 / MEDIUM
- **ESTIMATE:** 0.5h
- **BLOCKS:** none
- **DEPENDENCIES:** MER-10 (CI pipeline)
- **ACCEPTANCE CRITERIA:**
  - `.github/workflows/ci.yml` no longer uses `version: latest` for the linter; a pinned version is set and documented alongside the clang pin.
  - Rationale matches the repo's determinism posture (matches `verify-gen` philosophy).
  - Lint result is identical across two consecutive CI runs on an unchanged tree.

### MER-39 — Add Consumer.Close() for the not-Run lifecycle path
- **ID:** MER-39
- **TITLE:** Plug ringbuf fd leak when `Consumer.New` succeeds but `Run` is never called (close review A-4 / D-8)
- **PRIORITY:** P3 / LOW
- **ESTIMATE:** 1h
- **BLOCKS:** none
- **DEPENDENCIES:** MER-27 (supervisor/runner now owns component lifecycles — the stated trigger)
- **ACCEPTANCE CRITERIA:**
  - `telemetry.Consumer` exposes `Close()` that releases the ringbuf reader fd on the New-but-never-Run path.
  - Supervisor lifecycle invokes it on shutdown for components it constructs but does not start.
  - T1 test asserts no fd leak across New→Close without Run.

### MER-40 — ADR for CC-1 original-destination recovery (TPROXY vs eBPF DNAT)
- **ID:** MER-40
- **TITLE:** Write the gating ADR for original-destination recovery (CC-1)
- **PRIORITY:** P1 / HIGH (Phase-4 entry gate; ROADMAP "highest-leverage blocker")
- **ESTIMATE:** 3–4h
- **BLOCKS:** Phase 4 (A-5 TPROXY plumbing, P4.x proxy mTLS), any proxy interception work
- **DEPENDENCIES:** ADR-0002 (Geneve topology — may add a new map if DNAT path chosen)
- **ACCEPTANCE CRITERIA:**
  - New ADR (next free number — see MER-41 for numbering) records the decision: **TPROXY + `IP_TRANSPARENT`** (recommended, Istio-ztunnel-style) vs eBPF DNAT-to-loopback + pinned `orig_dst_map`.
  - Captures consequences for agent (rule installation), proxy (transparent listeners), and the eBPF schema (possible new map).
  - Marked as a **Phase-4 entry gate** in ROADMAP; references the no-TLS echo prototype mitigation.

### MER-41 — Reconcile ADR numbering & backfill ADR-0005 tracking
- **ID:** MER-41
- **TITLE:** Fix ADR index gap (0004 empty, 0005 present, untracked) and backfill ticket linkage
- **PRIORITY:** P2 / MEDIUM
- **ESTIMATE:** 1h
- **BLOCKS:** MER-34 (which authors ADR-0004; numbering must be unambiguous)
- **DEPENDENCIES:** none
- **ACCEPTANCE CRITERIA:**
  - The 0004 slot is reserved/explained: MER-34 still owns `0004-map-schema-freeze.md`; no other ADR claims 0004.
  - `docs/adr/0005-geneve-encap-failure-policy.md` is linked to a tracking ticket (it was authored with no MER reference); a one-line provenance note is added to the ADR.
  - An `docs/adr/README.md` (or index table) lists every ADR with its owning ticket and status, so future ad-hoc ADRs are caught.

### MER-42 — Phase-1 completion ledger vs git-history reconciliation
- **ID:** MER-42
- **TITLE:** Reconcile ticket-completion ledger against git history (MER-20/30 merged without MER-17/18)
- **PRIORITY:** P1 / HIGH (process / integration traceability)
- **ESTIMATE:** 2h
- **BLOCKS:** MER-18 (P1.1 gate), MER-34 (exit gate references all gates green)
- **DEPENDENCIES:** none
- **ACCEPTANCE CRITERIA:**
  - Documented status for MER-17 (verdict enforcement + decision-point emission): MER-20 (`tc_egress`) and MER-30 (metric slots) depend on it / its emission contract, yet MER-17 has no commit in history — confirm whether it was folded into MER-16 or is genuinely incomplete.
  - A status column/ledger is maintained in this `tickets.md` mapping every MER-id → {planned, in-progress, done+SHA, gate-status}.
  - Any dependency executed out of order (downstream merged before its upstream/gate) is flagged with remediation.

### MER-43 — Real-link VLAN parsing (lift V-2 passthrough limitation)
- **ID:** MER-43
- **TITLE:** Parse 802.1Q VLAN frames in `tc_ingress`/`tc_egress` for real pod links (close review V-2 / D-10)
- **PRIORITY:** P3 / LOW (deferred until real-link attach)
- **ESTIMATE:** 2–3h
- **BLOCKS:** Phase 1 real-link (non-veth) attach
- **DEPENDENCIES:** MER-16, MER-17 (parser + verdict path)
- **ACCEPTANCE CRITERIA:**
  - VLAN-tagged frames are unwrapped and the inner IPv4/L4 parsed (today they fall into non-IPv4 passthrough and are counted-but-unparsed).
  - T2 case: VLAN-tagged packet resolves identity and gets a verdict equal to the untagged equivalent.
  - MER-19's VLAN passthrough case is updated to reflect parsing (not passthrough) once real-link attach is in scope.

---

## Completion Ledger — MER-42 reconciliation (run 1, 2026-06-13)

Authoritative ticket→git reconciliation closing **MER-42**. Ground truth is the
git history `64148cc`…`a159f3c` (10 commits) cross-checked against the working
tree and the planned tickets in `docs/PHASE{0,1}_TICKETS.md`. SHAs are 7-char.

### Headline finding: MER-17 is **done-as-built**, not incomplete

The Batch-1 header (above) listed MER-17 as *Open* because no commit names it.
That is a **labeling gap, not a code gap**. The full MER-17 deliverable —
`policy_map` lookup keyed per D12 (incl. `direction`), `ALLOW→TC_ACT_OK`,
`DENY→TC_ACT_SHOT` + `denied_flows_map` upsert + event, `REDIRECT→`mark-only
placeholder + event, connection-open-only `flow_event` emission (TCP SYN /
UDP first-sight via bounded LRU), metric slots 2–5, and the `counter.c`
"toolchain-test-only" demotion — is present in `bpf/tc_ingress.c` today
(the file even carries a literal `MER-17 placeholder` comment on the REDIRECT arm).

That logic was added in commit **`754e2ee`**, whose subject is
*"feat(datapath): implement MER-26 writer and translation layer"* — i.e.
MER-17 was **folded, unlabeled, into the MER-26 commit** (verified:
`git show 754e2ee -- bpf/tc_ingress.c` adds the policy lookup, verdict switch,
`denied_flows_map`, and `emit_flow_event` calls; the earlier MER-16 commit
`e2d2fff` only removed inline map defs and rewired headers). MER-17 was **not**
folded into MER-16. Its emission/verdict contract — which MER-20 (`tc_egress`)
and MER-30 (metric slots) consume — therefore *does* exist, and both of those
downstream tickets merged **after** `754e2ee`, so the dependency order on disk
is sound even though the ledger order was wrong.

The same `754e2ee` commit also silently absorbed **MER-23** (policy compiler,
`internal/control/compiler.go` + goldens) and **MER-31** (flow aggregation +
`identitytable`, `internal/agent/telemetry/aggregate.go`). All three were
mis-tracked as *Open*. Corrected below.

### Ledger (every MER-id → status)

Status legend: **done** = code merged & matches acceptance; **done\*** = merged
but under a mislabeled commit (traceability defect, code complete);
**in-progress** = partially landed / gate scaffold not closed; **planned** = not
started. "Gate" flags the six Phase-1 gates.

| MER | Title (short) | Status | Commit(s) | Gate-status / note |
|----|----|----|----|----|
| 1–10 | Phase-0 toolchain spine, loaders, harness, CI | done | `64148cc`, **`2d8fed4`** | Phase-0 exit sign-off **CLOSED** — `PHASE0_REVIEW` APPROVED; gate log `docs/PHASE0_GATE_EVIDENCE.log` |
| 11 | ADR-0001 unknown-identity posture | done | `96ed323` | — |
| 12 | ADR-0002 Geneve placement | done | `96ed323` | File is `0002-geneve-topology.md` (planned name was `…-parse-placement`); naming tracked by **MER-41** |
| 13 | Module path / license / bpf2go prefix | done | `64148cc`, `96f9fdb` | `LICENSE` + `bpf/LICENSE`; bpf2go prefix in `gen.go` |
| 14 | Phase-1 contract freeze | done | `64148cc`, **`2d8fed4`** | Bindings committed (`counter`, `tcingress`, `tcegress` `*_bpfel.{go,o}`) |
| 15 | wire↔C equivalence + depguard wall | in-progress | `64148cc` (depguard) | depguard `pkg/wire` wall present in `.golangci.yml`; **`internal/agent/datapath/translate_test.go` absent** → equivalence test still owed |
| 16 | `tc_ingress.c` parser + identity | done | `e2d2fff` | — |
| **17** | **Verdict enforcement + decision-point emission** | **done\*** | **`754e2ee`** | **Folded unlabeled into the MER-26 commit.** Code complete (see headline). Relabel/annotate; no code work owed |
| 18 | **P1.1 GATE** — verdict matrix ≡ reference | in-progress (Gate) | `a03d198` | `test/bpf/verdict_test.go` landed under the *MER-30* commit with the redirect/policy rows `t.Skip`-ped "pending MER-17". MER-17 has since landed → **un-skip & assert; gate NOT closed** |
| 19 | Parser negative/regression suite | planned | — | `malformed_test.go`, `ringbytes_test.go` absent |
| 20 | `tc_egress.c` + Geneve option push | done | `1dee6f8` | — |
| 21 | **P1.3 GATE** — Geneve two-node | in-progress (Gate) | `a03d198` | `geneve_test.go` is a skipped stub waiting on MER-20 — **MER-20 landed (`1dee6f8`); skip not lifted; gate NOT closed** |
| 22 | Reference evaluator | done | `e2d2fff` | — |
| **23** | **Policy compiler** | **done\*** | **`754e2ee`** | **Folded unlabeled into the MER-26 commit**; `compiler.go` + 3 goldens present |
| 24 | **CP-2 GATE** — compiler ≡ reference property | planned (Gate) | — | `internal/control/conformance_test.go` absent |
| 25 | `attach.Manager` netlink | done | `64148cc` + `e2d2fff` | base in scaffold, unit test in the labeled MER-25 commit |
| 26 | `datapath.Writer` | done | `754e2ee` | labeled correctly |
| 27 | A-1 agent stub (YAML→snapshot→plan) | done | `e3d2cac` | — |
| 28 | Two-node harness | done | `e2d2fff` (+`2e04163` gofmt) | — |
| 29 | **P1.2 GATE** — live policy integration | in-progress (Gate) | `a03d198` | `policy_test.go` skipped stub waiting on MER-26/27 — **both landed (`754e2ee`,`e3d2cac`); skip not lifted; gate NOT closed** |
| 30 | Metrics reader + Prometheus endpoint | done | `13099db`,`a03d198`,`a159f3c` | — |
| **31** | **Flow aggregation + identity resolution** | **done\*** | **`754e2ee`** | **Folded unlabeled into the MER-26 commit**; `aggregate.go` + `identitytable` + tests present |
| 32 | **O-2 GATE** — denied-flows join + metrics | planned (Gate) | — | `metrics/denied.go`, `test/integration/metrics_test.go` absent |
| 33 | Schema version single-sourcing | done | `fbfc00d` | bpf2go-sourced `schemaVersion`; `loader_test.go` T2 fail-closed |
| 34 | **EXIT GATE** — ADR-0004 freeze + doc reconciliation | planned (Gate) | — | Stub reserved (`0004-map-schema-freeze.md`); full ADR blocked on the five gates above |
| **35** | **Phase-0 exit sign-off (F-1…F-4)** | **done** | **`2d8fed4`** | Phase 1 entry APPROVED; closes F-4 + **MER-60** |
| 36–40, 43 | Backlog batch 2026-06-13 | planned / done† | — | see individual tickets; †MER-40 done (`96f9fdb`) |
| **41** | **ADR index + 0004 reservation + ADR-0005 linkage** | **done** | **`96f9fdb` + MER-41 commit** | `docs/adr/README.md` registry; `0004` stub; ADR-0005 `Tracking ticket`/`Provenance` backfill |
| 42 | Ledger reconciliation | done | ledger in `tickets.md` | MER-17/23/31 relabeled; remediation → **MER-45** |

### Out-of-order executions & remediation

1. **Multi-ticket / mislabeled mega-commit `754e2ee`** ("MER-26") silently
   shipped **MER-17, MER-23, MER-31** (and authored ADR-0005). 
   *Remediation:* this ledger is the authoritative relabel; provenance recorded
   via `git notes` on `754e2ee` and `96f9fdb` (**MER-45** closed). Require
   one-ticket-per-commit (or an explicit `MER-x, MER-y` subject) going forward.
   ADR-0005's missing ticket linkage is handed to **MER-41** (closed).

2. **Gate scaffolds merged before their upstreams, then never re-armed.** The
   three Phase-1 gate tests — **MER-18** (`verdict_test.go`), **MER-21**
   (`geneve_test.go`), **MER-29** (`policy_test.go`) — were committed in
   `a03d198` (titled *MER-30*) as `t.Skip` stubs pending MER-17/MER-20/MER-26+27.
   **All those blockers have since landed, but every skip is still in place**, so
   **none of P1.1/P1.2/P1.3 are actually green** even though the dependency graph
   says they should be. 
   *Remediation (downstream of MER-42, in dep order):* lift the skips and assert
   on the now-present paths — MER-18 first (un-skip the redirect/policy-driven
   rows against MER-17's lookup), then MER-21 and MER-29 — and re-run on the 5.15
   target. **Do not mark any gate done until its skip is removed and the suite is
   green in CI.**

3. **`tc_egress` (MER-20) / metric slots (MER-30) authored against MER-17's
   contract while MER-17 was tracked Open.** On-disk order is fine (both merged
   after `754e2ee`); the defect was purely ledger drift — corrected above.

4. **Generated bpf2go bindings not committed** though `.gitignore` mandates it
   (F-4). Every load/`prog_test_run` gate (MER-16/17/18/21/29) implicitly depends
   on this; surfaced here, owned by **MER-35**.

---

## Batch 2026-06-13 (Backlog Manager run 2)

The MER-42 reconciliation (run 1) surfaced two **preventive** defects it
documented but did not itself ticket: (a) the three Phase-1 gate suites are
`t.Skip` stubs that CI scores as green even though their blockers have landed,
and (b) commit `754e2ee` shipped four untracked deliverables (MER-17/23/31 +
ADR-0005), i.e. there is no control preventing ledger drift from recurring.
Next free ID = MER-44.

### MER-44 — Gate-suite skip-integrity guard (no false-green gates)
- **ID:** MER-44
- **TITLE:** Fail CI when a Phase-1 gate suite contains skipped tests
- **PRIORITY:** P1 / HIGH (gate failure / false-green risk)
- **ESTIMATE:** 2h
- **BLOCKS:** MER-34 (exit gate trusts the five gates as green)
- **DEPENDENCIES:** MER-42 (surfaced that MER-18/21/29 are skipped stubs whose blockers landed)
- **ACCEPTANCE CRITERIA:**
  - CI fails if any test in the gate suites (`test/bpf/verdict_test.go`, `test/integration/{geneve,policy,metrics}_test.go`, `internal/control/conformance_test.go`) reports a skip — the skip count must be asserted `== 0` (e.g. parse `go test -json` for `"Action":"skip"`).
  - A gate (P1.1/P1.2/P1.3/CP-2/O-2) may be declared green only when its suite runs with zero skips and zero failures on the 5.15 target.
  - The rule is documented next to the gate definitions so future skip-stubs can't silently satisfy a gate.

### MER-45 — Commit→ticket traceability policy + backfill provenance
- **ID:** MER-45
- **TITLE:** Enforce one-ticket-per-commit subject linkage; backfill notes on `754e2ee`
- **PRIORITY:** P2 / MEDIUM (process; prevents recurrence of ledger drift)
- **ESTIMATE:** 1.5h
- **BLOCKS:** none (preventive)
- **DEPENDENCIES:** MER-42
- **ACCEPTANCE CRITERIA:**
  - `git notes` backfilled on `754e2ee` recording that it also implements MER-17, MER-23, MER-31 and authored ADR-0005.
  - A commit-message check (CI or hook) requires every `feat`/`fix` subject to name ≥1 `MER-<n>`, and a commit implementing multiple tickets must list all of them in the subject/body.
  - Contributing docs state the one-implementation-ticket-per-commit (or explicit multi-id) rule; the check rejects an unlabeled implementation commit.

**Status (2026-06-13): done** — git notes on `754e2ee` + `96f9fdb`; `scripts/check-mer-ticket-refs.sh` + `scripts/verify-provenance-notes.sh` in CI; see `docs/CONTRIBUTING.md` and `docs/provenance/mislabeled-commits.md`.

---

## Batch 2026-06-13 (Backlog Manager run 3)

State change since run 2: `LICENSE` + `bpf/LICENSE` landed (MER-13), ADR-0006
original-destination recovery authored (MER-40/CC-1), `docs/adr/README.md` added
(MER-41 partial → **closed**), and the MER-15/36/37/38/39 + gate-suite advances all landed —
but inside the **mislabeled mega-commit `96f9fdb` "impkement phase2"** (typo'd
subject, zero MER-ids, content is Phase-0/1 not Phase-2). No actual Phase-2
subsystem code exists yet. All findings this run are already owned by open
tickets (mislabel→MER-45, MER-24 skip→MER-44, ~~ADR-0004 gap→MER-41~~ **MER-41 closed**,
uncommitted bindings→MER-35) **except** the absence of any Phase-2 plan/entry
gate, filed below. Next free ID = MER-46.

### MER-46 — Phase-2 plan, ticket decomposition, and hard entry gate
- **ID:** MER-46
- **TITLE:** Author PHASE2_PLAN.md + PHASE2_TICKETS.md and install Phase-2-entry gate = MER-34 green
- **PRIORITY:** P1 / HIGH (planning/doc gap + sequencing guard; a commit already reaches for "phase2")
- **ESTIMATE:** 3–4h
- **BLOCKS:** any real Phase-2 implementation (gated sock_ops/sk_msg redirect, ADS-vs-stub, CP-3 conformance)
- **DEPENDENCIES:** MER-34 (Phase-1 exit gate) — Phase-2 code may not merge until MER-34 is green; planning doc itself has no dependency
- **ACCEPTANCE CRITERIA:**
  - `docs/PHASE2_PLAN.md` + `docs/PHASE2_TICKETS.md` exist, derived from ROADMAP week-4 scope (gated `sock_ops`+`sk_msg` redirect with the SOCKMAP-eligibility-is-a-verdict-flag invariant; ADS server vs agent stub + conformance suite CP-3) and the relevant subsystem specs; every ticket ≤4h with testable acceptance criteria, deps, and waves — same format as PHASE1_TICKETS.md.
  - A **Phase-2-entry gate** is recorded (in ROADMAP + the plan): no Phase-2 implementation ticket merges until MER-34 (Phase-1 exit) is green, mirroring the Phase-0→Phase-1 entry rule.
  - The "SOCKMAP eligibility is a policy verdict flag, not a perf toggle; absent the flag, no SOCKHASH insertion" invariant (ROADMAP CC-5 / eBPF R2) is captured as an explicit Phase-2 acceptance criterion with a permanent negative test.

---

## Batch 2026-06-13 (Backlog Manager run 4)

Strong run: MER-24 (CP-2 gate), MER-41 (ADR-0004 reserved + index), MER-45
(provenance + commit-linkage check), and MER-46 (Phase-2 PLAN/TICKETS/GATES,
IDs MER-47…MER-59) all landed in clean, properly-labeled commits — commit
hygiene is now holding. ADR sequence 0001–0006 + README is complete.
PHASE1_GATES.md, test/gates/manifest.txt, and the MER-44 skip-guard (CI +
Makefile) all verified present. The Phase-2 decomposition is well-formed and
correctly gated on MER-34.

No new design/test/ADR gaps surfaced. The **one** item filed below is the
extraction of a blocker stuck for four consecutive runs that is no longer
Phase-0-only. Global max ID is MER-59 (PHASE2_TICKETS); next free = MER-60.

### MER-60 — Commit generated bpf2go bindings (close F-4; cross-phase blocker)
- **ID:** MER-60
- **TITLE:** Generate and commit `*_bpfel.go`/`*_bpfel.o` bindings on the 5.15 target (close PHASE0_REVIEW F-4)
- **PRIORITY:** P0 / BLOCKER
- **ESTIMATE:** 1–2h (gated only on a working 5.15 VM/CI session)
- **BLOCKS:** MER-35 (Phase-0 sign-off), MER-47 (Phase-2 contract: "make ebpf regenerates bindings committed"), and every load/`prog_test_run` gate (MER-16/17/18/21/29/49/50/58)
- **DEPENDENCIES:** MER-1 (dev VM bring-up — `scripts/vm-*.sh` + `test/vm/*` work is in the tree, uncommitted)
- **ACCEPTANCE CRITERIA:**
  - `make vmlinux` + `make ebpf` run on the Ubuntu 22.04 / 5.15 target; the generated `bpf/*_bpfel.go` and `bpf/*_bpfel.o` for every program (`counter`, `tc_ingress`, `tc_egress`, and the Phase-2 `sock_ops`/`sk_msg` once MER-47 lands) are committed — `git ls-files | grep _bpfel` is non-empty.
  - `make verify-gen` run twice produces zero diff against the committed bindings (determinism gate, MER-8).
  - The VM bring-up scripts currently uncommitted in the working tree are committed under MER-1 with a proper subject (no further mega-commits).
  - Rationale: this prerequisite has been outstanding across Backlog Manager runs 1–4; promoting it out of MER-35's F-4 sub-bullet gives it a discrete owner and exposes its Phase-2 reach.

**Status (2026-06-13): done (via MER-35)** — counter/tcingress/tcegress bindings + VM scripts committed; sock_ops/sk_msg deferred to MER-47.

---

<!-- Future Backlog Manager runs append new dated batches below this line. -->
