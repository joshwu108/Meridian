# Phase 2 gate definitions

Phase 2 ships four **gates** plus one **entry gate** and one **exit gate**.
Gate suites follow the MER-44 skip-integrity rules in
[PHASE1_GATES.md](PHASE1_GATES.md): a gate is not green when its tests are
skipped.

## Entry gate — Phase-2 code blocked until Phase-1 exit

**No MER-47+ implementation ticket may merge until MER-34 is green.**

Prerequisites (all required):

| Prerequisite | Ticket | Evidence |
|---|---|---|
| P1.1 verdict matrix | MER-18 | `test/bpf/verdict_test.go`, armed=yes, 0 skips |
| P1.2 live policy integration | MER-29 | `test/integration/policy_test.go`, armed=yes, 0 skips |
| P1.3 Geneve two-node | MER-21 | `test/integration/geneve_test.go`, armed=yes, 0 skips |
| CP-2 compiler ≡ reference | MER-24 | `internal/control/conformance_test.go`, armed=yes, 0 skips |
| O-2 denied-flows metrics | MER-32 | `test/integration/metrics_test.go`, armed=yes, 0 skips |
| Phase-1 exit / schema freeze | MER-34 | ADR-0004 published; all five gates above referenced as green |

Planning artifacts (`PHASE2_PLAN.md`, `PHASE2_TICKETS.md`, this file) may land
before MER-34 closes — they do not constitute Phase-2 implementation.

Recorded in [ROADMAP.md](../ROADMAP.md) (week 4) and
[PHASE2_PLAN.md §0](PHASE2_PLAN.md).

## Gate inventory

| Gate ID | Ticket | Suite | Package / file |
|---------|--------|-------|----------------|
| P2.1-N | MER-49 | SOCKMAP-negative (CC-5 / eBPF R2) | `test/bpf/sockmap_negative_test.go` |
| P2.2 | MER-51 | Byte integrity + denied never redirected | `test/integration/sockmap_integrity_test.go` |
| P2.2-BENCH | MER-52 | Intra-node latency (nightly T4) | `test/integration/sockmap_bench_test.go` |
| CP-3 | MER-56 | ADS conformance + <500 ms propagation | `internal/control/ads/conformance_test.go` |
| EXIT | MER-59 | Doc reconciliation + Phase-3 entry | references all gates above |

### CC-5 sockmap invariant (load-bearing)

> SOCKMAP eligibility is a policy verdict flag, not a perf toggle; absent the
> flag, no SOCKHASH insertion.

Enforcement layers:

1. **Compile time** — `reference.Evaluator` and `control.Compiler` reject
   `SOCKMAP_ELIGIBLE` unless `action == ALLOW` and `¬L7_REQUIRED ∧ ¬MTLS_REQUIRED`
   (MER-22/23, already landed).
2. **Kernel path** — `sock_ops` checks `POLICY_FLAG_SOCKMAP_ELIGIBLE` before
   `bpf_sock_hash_update()` (MER-48).
3. **CI (permanent negative test)** — gate P2.1-N (MER-49) asserts DENY,
   L7-required, mTLS-required, REDIRECT, and ALLOW-without-flag flows never
   appear in `sockhash`. This test must never be deleted or skipped; it is a
   top-project risk mitigation (ROADMAP top risk #2).

## Gate status

| Gate | Ticket | Armed | State | Evidence |
|------|--------|-------|-------|----------|
| P2.1-N | MER-49 | **yes** | **GREEN** | `TestSockmapNegativeGate_MER49` — DENY / L7-required / mTLS-required / REDIRECT / ALLOW-without-flag all absent from `sockhash`; eligible ALLOW present. Real loopback connect on Lima 5.15; `make check-gate-skips` 0 skips. |
| P2.2 | MER-51 | **yes** | **GREEN** | `TestSockmapIntegrityGate_MER51` — eligible flow transfers 1 MiB byte-for-byte identical (sha256) AND is redirected (`METRIC_FLOWS_REDIRECTED` rises); after flipping the flow to DENY a new connection is not redirected (counter flat) while its bytes still flow. Production attach (bpfobj + attach managers, MER-57) on Lima 5.15; `make check-gate-skips` 0 skips. |
| P2.2-BENCH | MER-52 | no | pending | nightly T4 |
| CP-3 | MER-56 | no | pending | gated on MER-55 |

Layer 3 of the CC-5 invariant is now armed in CI: a regression that lets any
non-eligible verdict class enter `sockhash` fails P2.1-N.

## Skip-integrity rule

Same as Phase 1 (MER-44):

1. Manifest row in `test/gates/manifest.txt` has `armed=yes`.
2. `make check-gate-skips` reports **0 skips** for that test on 5.15.
3. Suite reports **0 failures**.

Gate stubs for Phase 2 start `armed=no` until their upstream tickets merge.

### Planned manifest rows (armed=no until implementation)

```text
# P2.1-N — MER-49 SOCKMAP permanent negative (CC-5)
no bpf ./test/bpf/... TestSockmapNegativeGate_MER49

# P2.2 — MER-51 byte integrity + denied never redirected
no integration ./test/integration/... TestSockmapIntegrityGate_MER51

# CP-3 — MER-56 ADS conformance + propagation SLA
no '' ./internal/control/ads/... TestADSConformanceGate_MER56
```

P2.2-BENCH (MER-52) is nightly T4 only — not in the PR gate manifest.

## Exit gate — Phase-3 entry

**Phase 3 implementation (agent netlink lifecycle A-2, ADS client A-3) may not
start until MER-59 is green** and all four armed gates above are green with CI
links recorded.

Phase 2 exit criteria (ROADMAP week 4):

- Denied flow never SOCKMAP-redirected (P2.1-N + P2.2).
- REST policy change visible in ADS stub < 500 ms (CP-3).
