# Active Ticket

ID: MER-49

Title: P2.1-N gate — permanent SOCKMAP-negative test (CC-5 / eBPF R2)

Objective:
Lock the CC-5 gated-insertion invariant that MER-48 just made live, BEFORE the
`sk_msg` redirect consumer (MER-50) lands. Add a permanent, armed, table-driven
negative test proving every NON-eligible verdict class never enters `sockhash`,
with an eligible control proving presence. Arm the P2.1-N gate so CI fails if any
future change lets a denied / L7-required / mTLS-required / REDIRECT / plain-ALLOW
socket become SOCKMAP-redirectable — the standing guard for ROADMAP Top-risk #2 /
eBPF R2 (silent mTLS/L7/policy bypass via a wrongly-inserted socket).

This is a TEST + GATE-ARMING ticket only. The kernel behavior is already correct
(MER-48); do NOT modify `sock_ops.c`, `meridian_helpers.h`, or any frozen schema.

Dependencies:
- MER-48 (DONE `77540ce`): `sock_ops` gated insertion + `meridian_helpers.h`.
  Reuse the `bpftest` helpers it added: `loadSockOps`, `establish`,
  `currentCgroupV2Path`, `sockhashHasKey` / `waitKeyPresent`, `sockKeyFor`,
  plus `seedPolicy` / `seedIdentity` — do NOT fork a second harness.
- MER-22 (DONE, Phase 1): `reference.Evaluator` already rejects `SOCKMAP_ELIGIBLE`
  unless `ALLOW ∧ ¬L7 ∧ ¬mTLS` (the compiler-side half of CC-5). This ticket is
  the KERNEL-side permanent guard of the same invariant.
- ADR-0007 (§"Gated insertion invariant" names MER-49 as the permanent
  enforcement test), CC-5, MER-44 (skip-integrity: an armed gate must report
  0 skips — the test must RUN, not skip, on the 5.15 CI target).

Acceptance Criteria:
1. New `test/bpf/sockmap_negative_test.go` defines `TestSockmapNegativeGate_MER49`
   (exact, stable name — it becomes the MER-44 manifest gate row).
2. Table-driven over the non-eligible verdict classes, each establishing a real
   flow and asserting the socket is ABSENT from `sockhash`:
   - DENY
   - ALLOW + `POLICY_FLAG_L7_REQUIRED`
   - ALLOW + `POLICY_FLAG_MTLS_REQUIRED`
   - REDIRECT
   - ALLOW without `POLICY_FLAG_SOCKMAP_ELIGIBLE`
   A control row ALLOW + `POLICY_FLAG_SOCKMAP_ELIGIBLE` asserts PRESENCE (so the
   test fails if the gate is trivially passing because nothing ever inserts).
3. Reuses the MER-48 helpers (no duplicate cgroup/connect/iteration harness);
   absence is asserted only AFTER allowing time for any erroneous insertion to
   land (no false-green from checking too early — mirror the MER-48 deny subtest).
4. The test RUNS on the 5.15 CI target (cgroup v2 present on ubuntu-22.04 / Lima)
   and reports ZERO skips — required because the row becomes `armed=yes`.
5. `test/gates/manifest.txt`: flip the P2.1-N row
   (`TestSockmapNegativeGate_MER49`) from `armed=no` to `armed=yes`.
6. `docs/PHASE2_GATES.md`: mark P2.1-N green and cite the committed evidence.
7. `make check-gate-skips` reports 0 skips / 0 failures with P2.1-N now armed and
   green; `make test-bpf` (incl. P1.1) and `make test-integration` stay green;
   `git status` clean; `make check-commits` passes (MER-49 ref, MER-45 linkage).

Files Expected To Change:
- test/bpf/sockmap_negative_test.go (new — TestSockmapNegativeGate_MER49 matrix)
- test/gates/manifest.txt              (P2.1-N row armed=no → armed=yes)
- docs/PHASE2_GATES.md                 (P2.1-N green + committed evidence)

Required Tests:
- `make test-bpf`         → TestSockmapNegativeGate_MER49 green (all non-eligible absent, eligible present) + P1.1 matrix green
- `make check-gate-skips` → 0 skips, 0 failures; P2.1-N now armed and green
- `make test-integration` → Phase-1 integration gates still green
- `make check-commits`    → MER-49 commit-linkage satisfied

Commit Message:
test(ebpf): MER-49 arm P2.1-N permanent SOCKMAP-negative gate (CC-5/eBPF R2)
