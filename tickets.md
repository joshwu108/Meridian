# Meridian Backlog — Generated Tickets

Living ledger maintained by the **Backlog Manager**. Planned tickets MER-1 … MER-34
live in `docs/PHASE0_TICKETS.md` and `docs/PHASE1_TICKETS.md`; Phase-2 tickets
MER-47 … MER-59 live in `docs/PHASE2_TICKETS.md`. **This file lists only open
backlog tickets (MER-35+) that are not yet implemented.**

Completed backlog tickets (MER-35, MER-36, MER-37, MER-38, MER-39, MER-40,
MER-41, MER-42, MER-44, MER-45, MER-46, MER-60) are removed from this file;
see git history and `docs/PHASE0_REVIEW.md` for sign-off and closure SHAs.

Next free ID = **MER-67**.

---

## Open backlog tickets

_(none)_

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
| MER-50 … MER-59 | `docs/PHASE2_TICKETS.md` | **IN PROGRESS.** Active: **MER-50** (`sk_msg` SOCKHASH redirect + SK_PASS fall-through) — the redirect consumer, now safe to build under the P2.1-N gate. MER-51/52/53/57/58 downstream per the Phase-2 dependency graph. |

---

<!-- Future Backlog Manager runs append new dated batches below this line. -->

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
