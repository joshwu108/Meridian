# Meridian Backlog — Generated Tickets

Living ledger maintained by the **Backlog Manager**. Planned tickets MER-1 … MER-34
live in `docs/PHASE0_TICKETS.md` and `docs/PHASE1_TICKETS.md`; Phase-2 tickets
MER-47 … MER-59 live in `docs/PHASE2_TICKETS.md`. **This file lists only open
backlog tickets (MER-35+) that are not yet implemented.**

Completed backlog tickets (MER-35, MER-36, MER-37, MER-38, MER-39, MER-40,
MER-41, MER-42, MER-44, MER-45, MER-46, MER-60) are removed from this file;
see git history and `docs/PHASE0_REVIEW.md` for sign-off and closure SHAs.

Next free ID = **MER-65**.

---

## Open backlog tickets

_(none)_

---

## Open work tracked elsewhere

These are **not** duplicated here; see the phase ticket files:

| IDs | Where | Status (summary) |
|-----|-------|----------------|
| MER-15, MER-18, MER-19, MER-21, MER-24, MER-29, MER-32, MER-34 | `docs/PHASE1_TICKETS.md` | Phase-1 gates and remaining deliverables |
| MER-47 … MER-59 | `docs/PHASE2_TICKETS.md` | Blocked on MER-34 (Phase-1 exit) |

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
