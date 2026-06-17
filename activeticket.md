# Active Ticket

ID: MER-69

Title: Phase-3 planning — decompose A-2 / A-3 / PKI-1/2 into tickets, gates, and the CC-2 ADR

Objective:
Phase 2 is COMPLETE (MER-59 EXIT green; all 9 gates deterministic; Agent SOCKMAP
lane closed by MER-58 `a8cf82a`). Plan Phase 3 the way MER-46 planned Phase 2:
produce the Phase-3 planning artifacts, decompose the ROADMAP week-5/6 scope into
ticket-sized units with a dependency graph and gate definitions, and schedule the
CC-2 wire-contract ADR. Pure planning docs — no production code, no Phase-3
implementation (that is gated on these artifacts landing).

Stay in scope: the three Phase-3 planning docs + the ROADMAP phase-gate row + ID
reservations. Do NOT implement A-2/A-3/PKI, do NOT write the CC-2 ADR body here
(only schedule it), and do NOT touch Phase-2 code or the frozen schema.

Dependencies:
- MER-59 (Phase-2 EXIT) green — Phase 3 is unblocked. Planning has **no** other
  dependency and may proceed now (mirrors MER-46, which planned Phase 2 while
  Phase-1 gates were still open).
- Inputs: ROADMAP.md (week 5–6 / PRD phase 3: A-2 agent netlink lifecycle, A-3 ADS
  client + xDS→CommitPlan translation, PKI-1/2 CA primitives + node bootstrap);
  ARCHITECTURE.md xDS-apply-pipeline + D20/D21; the MER-54 interim encoding flagged
  CC-2-pending (D21/MER-67); cross-cutting CC-2 (wire contract) and CC-4 (bootstrap
  credential).

Acceptance Criteria:
1. `docs/PHASE3_PLAN.md` — Phase-3 scope, workstream split (A kernel/agent vs B
   PKI), build order, top risks, and the dependency graph (text), mirroring
   `PHASE2_PLAN.md`.
2. `docs/PHASE3_TICKETS.md` — A-2 / A-3 / PKI-1/2 decomposed into ticket-sized
   units (IDs reserved from MER-70+), each with scope, dependencies, and the files
   it will touch; A-3 explicitly consumes the MER-54 ADS server and replaces the
   MER-55 stub on the agent side.
3. `docs/PHASE3_GATES.md` — Phase-3 gate inventory + the **exit gate**: ROADMAP
   week-5/6 criterion **"REST → kernel map < 500 ms measured end-to-end"** (real
   policy lands in the kernel via the agent A-3 translation), plus the A-2/A-3
   entry gates referenced from PHASE2_GATES.
4. The **CC-2 compiled-policy + xDS resource wire-contract ADR** is scheduled as a
   Phase-3 deliverable (its own reserved ticket), cross-referenced to D21 / MER-67
   (interim JSON-in-BytesValue encoding to be superseded). Note CC-4 (single node
   bootstrap credential) as the PKI bootstrap input.
5. `ROADMAP.md` "Phase entry gates" table updated so Phase 2→3 reflects MER-59
   green; `tickets.md` "Next free ID" advanced past the reserved Phase-3 IDs.
6. No production code; `go build ./...` unaffected; `make check-commits` passes
   (MER-69 ref); `git status` clean after commit.

Files Expected To Change:
- docs/PHASE3_PLAN.md      (new — Phase-3 plan, mirrors PHASE2_PLAN.md)
- docs/PHASE3_TICKETS.md   (new — A-2/A-3/PKI-1/2 decomposed, IDs MER-70+)
- docs/PHASE3_GATES.md     (new — gate inventory + REST→kernel <500 ms exit gate)
- ROADMAP.md               (Phase 2→3 entry-gate row; CC-2 scheduled)
- tickets.md               (reserve Phase-3 IDs; advance Next free ID)

Required Tests:
- `make check-commits`   → MER-69 commit-linkage satisfied
- `go build ./...`       → unaffected (docs-only change)
- internal consistency: every Phase-3 ticket ID is unique, dependency graph is acyclic, exit gate is measurable

Commit Message:
docs(phase3): MER-69 Phase-3 plan — A-2/A-3/PKI decomposition, gates, CC-2 ADR scheduled
