# Active Ticket

ID: MER-59

Title: EXIT GATE — Phase-2 doc reconciliation + Phase-3 entry rule

Objective:
Close Phase 2. Reconcile the documentation to the as-built state, record a single
green-evidence run for every Phase-2 gate, declare Phase 2 complete, and state the
Phase-3 entry rule. This is the EXIT gate: all join deps are now satisfied
(MER-49 ✅ P2.1-N, MER-51 ✅ P2.2, MER-56 ✅ CP-3, MER-52 ✅ P2.2-BENCH). Pure docs +
a verification run — no production code. Verify gates are GENUINELY green before
declaring (cite a real Lima 5.15 / CI run; do not assert green on stale evidence).

Stay in scope: `docs/PHASE2_GATES.md`, `README.md`, `ROADMAP.md`,
`docs/ARCHITECTURE.md`. Do NOT modify production code, arm/disarm gates, or start
Phase-3 work. The ADS architecture decision (D21) is tracked separately by MER-67
(open, off critical path) — reference it as a known follow-up; do NOT block Phase-2
exit on it.

Dependencies:
- MER-49 (P2.1-N) `d0125c1`, MER-51 (P2.2) `f7642c9`, MER-56 (CP-3) `2898a75`,
  MER-52 (P2.2-BENCH) `17bc526` — all CLOSED. All four MER-59 joins satisfied.
- ADR-0004 (frozen map schema) must be unchanged — the Phase-3 entry rule asserts it.
- Verification: run the full armed-gate suite on the Lima `meridian` VM (5.15) —
  `make test-bpf`, `make test-integration`, `make check-gate-skips` (0 skips across
  the 9 armed gates) — and the nightly `make test-e2e` for the bench. Cite the real
  result. (Lima recipe: `GOMODCACHE=/Users/joshuawu/go/pkg/mod GOFLAGS=-mod=mod
  GOPROXY=off`, the VM has no network.)

Acceptance Criteria:
1. `docs/PHASE2_GATES.md`: the "Gate status" table lists **every** Phase-2 gate
   with its real evidence — P2.1-N (MER-49), P2.2 (MER-51), CP-3 (MER-56) all
   **GREEN, armed=yes, 0 skips** with the Lima 5.15 / CI run cited; P2.2-BENCH
   (MER-52) recorded as a **nightly non-gate** with its honest result ("no win on
   5.15.0-179: p50 +6.3%, p99 +281.7%", redirect engaged) — not green-washed.
2. `README.md`: Status line updated to **"Phase 2 — complete (MER-59 exit)"** with
   a one-line summary (SOCKMAP redirect + CC-5 fail-closed gates + ADS/CP-3).
3. `ROADMAP.md`: the week-4 / Phase-2 **exit criteria checked off** — "denied flow
   never SOCKMAP-redirected" (MER-49 static + MER-51 runtime) and
   "policy-change-to-stub < 500 ms" (MER-56, measured ~1.3 ms). The Phase 2→3
   entry-gate row reflects MER-59 green.
4. `docs/ARCHITECTURE.md`: confirm **D18–D20** are recorded as-built (they are —
   verify they match shipped behavior); add a one-line pointer that the ADS
   server's decision (**D21**) is pending under MER-67 (interim xDS encoding,
   CC-2-pending), so the gap is explicit, not silent.
5. **Phase-3 entry rule stated** (in ROADMAP and/or PHASE2_GATES): Phase 3 may
   start when **MER-59 is green AND ADR-0004 frozen schemas are unchanged**;
   reference the Phase-3 first gates (A-2/A-3).
6. No production code touched; `go build ./...` / `go vet ./...` unaffected;
   `make check-commits` passes (MER-59 ref); `git status` clean after commit.

Files Expected To Change:
- docs/PHASE2_GATES.md     (fill the gate-status table: P2.2 + CP-3 GREEN evidence; BENCH as nightly non-gate)
- README.md               (Status → Phase 2 complete)
- ROADMAP.md              (check off week-4 exit criteria; Phase 2→3 entry row)
- docs/ARCHITECTURE.md    (confirm D18–D20 as-built; pointer to D21/MER-67 pending)

Required Tests:
- `make test-bpf` / `make test-integration` / `make check-gate-skips` (Lima 5.15) → 9 armed gates green, 0 skips (evidence for PHASE2_GATES.md)
- `make test-e2e` (Lima 5.15) → bench runs, result recorded (already committed `17bc526`)
- `go build ./...` / `go vet ./...` → unaffected (docs-only change)
- `make check-commits` → MER-59 commit-linkage satisfied

Commit Message:
docs(phase2): MER-59 Phase-2 EXIT — gate reconciliation + Phase-3 entry rule
