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
| P2.2-BENCH | MER-52 | n/a (nightly) | **MEASURED** | `TestSockmapBench` (`e2e` tag) on Lima 5.15.0-179 — intra-node connect+first-byte, eligible vs baseline. **No latency win for short flows: p50 +6.3%, p99 +281.7% (a regression); redirect engaged (+4400).** Not a PR gate; result in `test/integration/testdata/sockmap_bench.json`. See the SOCKMAP rationale note in [ARCHITECTURE.md](ARCHITECTURE.md). |
| CP-3 | MER-56 | **yes** | **GREEN** | `TestADSConformanceGate_MER56` — ADS conformance (initial / add / delete / NACK-recovery / stale-nonce-ignored / reconnect) over `bufconn`, plus REST `POST /policies` → stub `Snapshot()` measured ~1.3 ms (< 500 ms budget). Pure-Go; `make check-gate-skips` 0 skips on Lima 5.15. |

Layer 3 of the CC-5 invariant is now armed in CI: a regression that lets any
non-eligible verdict class enter `sockhash` fails P2.1-N.

**Whole-suite evidence (MER-59 exit):** `make check-gate-skips` reports **0 skips
and 0 failures across all nine armed gates** (P1.1, P1.2, P1.3, CP-2 ×2, O-2,
P2.1-N, P2.2, CP-3) on the Lima `meridian` VM (kernel 5.15.0-179), 2026-06-16.
Known harness caveat: the privileged bpf/integration gates leak netns/bpffs/cgroup
state, so back-to-back runs (or runs overlapping another test process) can flake
non-deterministically — a clean reap (`make test-clean`) between privileged suites
is required for a reliable run; each gate also passes in isolation. Tracked as a
test-isolation follow-up; it is not a production-code regression. CI confirmation
follows on branch push (these Phase-2 commits are not yet on `origin`).

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

**MER-59 is GREEN — Phase 2 is complete.** All four armed Phase-2 gates
(P2.1-N, P2.2, CP-3) plus the carried-forward Phase-1 gates pass with 0 skips on
Lima 5.15 (see "Whole-suite evidence" above); the nightly P2.2-BENCH (MER-52) has
been measured.

**Phase-3 entry rule:** Phase 3 implementation (agent netlink lifecycle A-2, ADS
client A-3) may start now that **(1) MER-59 is green AND (2) the ADR-0004 frozen
map schemas are unchanged.** The first Phase-3 gates are A-2 (agent netlink
lifecycle) and A-3 (ADS client + translation).

Phase 2 exit criteria (ROADMAP week 4) — **both met:**

- ✅ Denied flow never SOCKMAP-redirected — P2.1-N (MER-49, static negative) +
  P2.2 (MER-51, runtime: denied flow never redirected).
- ✅ REST policy change visible in ADS stub < 500 ms — CP-3 (MER-56), measured
  ~1.3 ms.

Open Phase-2 follow-ups (do NOT block exit): MER-58 (agent sockhash re-open
restart test) and MER-67 (ARCHITECTURE D21 for the ADS server + interim
xDS-encoding note). Both are off the exit critical path.
