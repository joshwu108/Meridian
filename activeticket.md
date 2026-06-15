# Active Ticket

ID: MER-51

Title: P2.2 GATE — SOCKMAP byte integrity + denied-never-redirected (runtime CC-5 proof)

Objective:
Arm the P2.2 gate: a T3 integration test proving the intra-node SOCKMAP fast path
(1) moves application bytes correctly and (2) never redirects a denied flow at
RUNTIME. MER-49 statically proves non-eligible verdicts never enter `sockhash`;
MER-51 is the complementary *runtime* proof — with the agent's production
managers (MER-57) actually attached, a real ≥1 MiB transfer over an eligible
flow arrives byte-for-byte identical to a plain-TCP baseline, and flipping the
flow's policy to DENY stops it completing via the redirect path. Together they
close ROADMAP Top-risk #2 / eBPF R2 (silent mTLS/L7/policy bypass) as a standing
merge blocker.

This is a TEST + GATE-ARMING ticket. The datapath is already correct (MER-48/50)
and attach is already productionized (MER-57); do NOT modify `sock_ops.c`,
`sk_msg.c`, the attach managers, or any frozen schema. Do not fold in the MER-52
latency benchmark.

Dependencies:
- MER-50 (DONE `c699887`): sk_msg redirect.
- MER-57 (DONE `014bc2e`): production attach — use `bpfobj.LoadSockOps`/`LoadSkMsg`
  + `attach.CgroupSockOpsManager`/`SkMsgSockhashManager` to attach (mirror
  production, not ad-hoc test attach). NOTE: the MER-50/57 bpf-tag helpers live
  in package `bpftest` (tag `bpf`) and are NOT importable from `test/integration`
  (tag `integration`); this suite needs its own setup built on `test/harness` +
  the production loaders/managers.
- ADR-0007 (CC-5 gated insertion / sole reader). MER-49 is the static half of the
  same invariant; MER-51 is the runtime half.

Acceptance Criteria:
1. New `test/integration/sockmap_integrity_test.go` defines a stable
   `TestSockmapIntegrityGate_MER51` (becomes the MER-44 manifest gate row).
2. Two-endpoints-same-node topology with distinct identities (reuse the loopback
   two-IP / netns pattern the MER-50/57 path uses); attach `sock_ops` + `sk_msg`
   via the **production** bpfobj loaders + attach managers, not inline raw attach.
3. **Byte integrity:** an eligible (`ALLOW + SOCKMAP_ELIGIBLE`) flow transfers
   **≥1 MiB**; received bytes are byte-for-byte identical to sent (compare a hash
   or full buffer). Prove correctness against a baseline plain-TCP transfer of the
   same payload (no SOCKMAP attach) — no corruption, no truncation, no short read.
4. **Denied never redirected (runtime):** with the eligible flow redirecting,
   flip its policy to DENY (and/or evict from `sockhash`); assert subsequent sends
   do NOT complete via the SOCKMAP redirect path (fall through or fail per stack),
   and that a flow denied from the start never SOCKMAP-redirects
   (`METRIC_FLOWS_REDIRECTED` does not move for it).
5. Runs on the 5.15 target with **zero skips**; flip the P2.2 row in
   `test/gates/manifest.txt` (`TestSockmapIntegrityGate_MER51`) `armed=no → yes`.
6. `make check-gate-skips` reports 0 skips / 0 failures across all now-EIGHT armed
   gates including P2.2.
7. No regression: `make test-bpf`, `make test-integration` green; `make ebpf`
   leaves the tree clean (test + manifest only — NO `bpf/*.c`/`.o` change);
   `git status` clean; `make check-commits` passes (MER-51 ref).

Files Expected To Change:
- test/integration/sockmap_integrity_test.go (new — TestSockmapIntegrityGate_MER51)
- test/gates/manifest.txt                    (P2.2 row armed=no → yes)
- docs/PHASE2_GATES.md                        (P2.2 armed/green + committed evidence)

Required Tests:
- `make test-integration` → TestSockmapIntegrityGate_MER51 green (1 MiB integrity + DENY-not-redirected)
- `make check-gate-skips` → 0 skips, 0 failures across all 8 armed gates (incl. P2.2)
- `make test-bpf`         → P1.1 + MER-48/49/50/57 still green (no regression)
- `make check-commits`    → MER-51 commit-linkage satisfied

Commit Message:
test(ebpf): MER-51 arm P2.2 gate — SOCKMAP byte integrity + denied-never-redirected
