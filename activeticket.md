# Active Ticket

ID: MER-82

Title: P0 — P1.3 armed gate RED on Lima 5.15.0-181: triage + restore 11/11 armed gates green

Objective:
The MER-71 closing commit (`02825e7`) reports the Lima gate run with
**P1.3 (`TestGeneveIngressIdentityPolicyGate_MER21`) FAILING**, dismissed in
the commit body as "pre-existing failure unrelated." An ARMED merge-blocker
gate red at HEAD is a MER-44 integrity violation regardless of which change
caused it (MER-66 precedent: P1.3 red = P0). Triage and fix.

Context/leads (from the audit):
- The Lima VM kernel moved **5.15.0-179 → 5.15.0-181** between evidence runs
  (MER-73 closed on -179; MER-71 evidence cites -181). A kernel point-release
  change to Geneve/TC behavior is a plausible trigger.
- The other prime suspect is the **dual-runner collision** (MER-68 finding: a
  second gate runner in the same VM corrupts runs — netns/pin cleanup races).
- A real regression from a Phase-2/3 commit is possible but less likely: no
  committed change since `630f616` touches the Geneve path (verify).

Do NOT modify the frozen ADR-0004 map schemas. Any eBPF `.o` regeneration
must go through the pinned deterministic toolchain (D10). Do NOT green-wash:
if the gate is genuinely red, the fix must make it genuinely green; do not
disarm the row, widen budgets, or re-run until lucky.

Dependencies:
- None. Requires Lima 5.15 root access, **ISOLATED window** with the MER-68
  competing-process guard (instrument and verify no second runner before
  trusting any result).

Acceptance Criteria:
1. Reproduce P1.3 at HEAD in a verified-isolated window; capture which
   sub-case fails (allow-path connect vs deny-path timeout) and the full
   failure output into `docs/PHASE1_GATE_EVIDENCE.log`.
2. Root-cause disposition, exactly one of:
   (a) kernel -179→-181 behavior change — document it and fix test/program
       within ADR-0002/ADR-0005 constraints;
   (b) collision artifact — prove with the competing-process guard, then
       show a clean-window pass (and record the collision evidence);
   (c) real regression — bisect to the introducing commit, minimal fix, cite
       the SHA in the commit body.
3. `limactl shell meridian -- make check-gate-skips` → **11/11 armed gates
   green, 0 skips, 0 failures** in an isolated window at HEAD (or HEAD+fix).
4. Evidence recorded: `docs/PHASE1_GATE_EVIDENCE.log` (P1.3 re-pass with
   kernel + date) and `docs/PHASE3_GATES.md` footnote if relevant.
5. Root-cause note committed so "pre-existing failure unrelated" is never
   again a gate disposition (MER-44 hygiene).
6. Host battery clean (`go build ./...`, `go vet ./...`,
   `go test -race ./internal/...`, `go mod tidy` no diff); commit(s)
   MER-82-linked; `make check-commits` passes; tree clean; branch pushed.

Files Expected To Change:
- docs/PHASE1_GATE_EVIDENCE.log            (failure capture + re-pass evidence)
- bpf/tc_egress.c / bpf/tc_ingress.c        (ONLY if disposition (a)/(c) requires;
                                             regen .o via pinned clang per D10)
- test/integration/geneve_test.go           (ONLY if the test itself must adapt)
- docs/PHASE3_GATES.md                      (footnote, if relevant)

Required Tests:
- `limactl shell meridian -- make test-integration` (ISOLATED, guarded) → P1.3 green
- `limactl shell meridian -- make check-gate-skips`                      → 11/11, 0 skips, 0 failures
- `go build ./...` / `go vet ./...` / `go test -race ./internal/...`     → clean
- `make check-commits`                                                   → MER-82 linkage

Commit Message:
fix(gates): MER-82 P1.3 Geneve gate red on 5.15.0-181 — <root cause> + restore 11/11 armed green
