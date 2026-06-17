# Phase 3 gate definitions

Phase 3 ships two **gates** plus one **entry gate** and one **exit gate**. Gate
suites follow the MER-44 skip-integrity rules ([PHASE1_GATES.md](PHASE1_GATES.md))
and the MER-68 determinism rule (privileged gates run one runner per VM, whole
package per `go test -parallel 1`; see [PHASE2_GATES.md](PHASE2_GATES.md)).

## Entry gate — Phase-3 code blocked until Phase-2 exit

**No MER-71+ implementation ticket may merge until MER-59 is green AND ADR-0004
frozen schemas are unchanged.**

| Prerequisite | Ticket | Evidence |
|---|---|---|
| Phase-2 exit | MER-59 | `d8c7612` (+ MER-68 `1b5bdf3` deterministic harness); all 9 armed gates green, 0 skips |
| Frozen map schema unchanged | ADR-0004 | `MERIDIAN_SCHEMA_VERSION = 2`; no schema delta in Phase 3 |

MER-59 is green at HEAD, so the entry gate is **satisfied**. Planning artifacts
(this file, PHASE3_PLAN, PHASE3_TICKETS) and the CC-2 ADR (MER-70) may land with
no entry dependency — they are not Phase-3 implementation.

## Gate inventory

| Gate ID | Ticket | Suite | Package / file |
|---------|--------|-------|----------------|
| A-2 | MER-71 | veth attach lifecycle (T3, root/Linux) | `test/integration/linkwatch_test.go` |
| **A-3 (EXIT criterion)** | MER-73 | REST→kernel `policy_map` < 500 ms (T3) | `test/integration/rest_to_kernel_test.go` |
| PKI-1 | MER-74 | CA / CSR / signing unit gate (T1, pure-Go) | `internal/control/ca/..._test.go` |
| EXIT | MER-76 | doc reconciliation + Phase-4 entry rule | references all gates above |

## Gate status

| Gate | Ticket | Armed | State | Evidence |
|------|--------|-------|-------|----------|
| A-2 | MER-71 | no | pending | gated on MER-71 |
| A-3 | MER-73 | no | pending | gated on MER-71 + MER-72 |
| PKI-1 | MER-74 | no | pending | gated on MER-74 |

Gate stubs start `armed=no` until their upstream tickets merge (MER-44).

### Planned manifest rows (armed=no until implementation)

```text
# A-2 — MER-71 netlink veth attach lifecycle
no integration ./test/integration/... TestVethAttachLifecycleGate_MER71

# A-3 — MER-73 REST→kernel propagation < 500 ms (Phase-3 exit criterion)
no integration ./test/integration/... TestRestToKernelPropagationGate_MER73

# PKI-1 — MER-74 CA / CSR / signing
no '' ./internal/control/ca/... TestCAPrimitivesGate_MER74
```

## A-3 propagation gate (load-bearing)

> A REST policy change must be visible in the **kernel `policy_map`** within
> **500 ms** end-to-end — measured by polling (`WaitUntil`), never `time.Sleep`.

This is PRD success criterion #4, measured for real: the Phase-2 CP-3 gate
(MER-56) measured REST→**stub** (~1.3 ms in-process); Phase 3 measures
REST→control→ADS→agent→**kernel**, the full live path. The agent ACKs only after
the `CommitPlan` is applied, so the metric measures truth (ARCHITECTURE xDS apply
pipeline). The gate also asserts NACK-on-malformed holds last-known-good and that
a policy shrink never transiently widens allows.

## Exit gate — Phase-4 entry

**Phase 4 implementation (TPROXY plumbing A-5, proxy redirect/echo P4.1, mTLS)
may not start until MER-76 is green** AND, per ROADMAP, the **CC-1 echo prototype
(ADR-0006)** proves a redirected connection reaches the proxy with the correct
original destination — the Phase-3→4 entry gate. CC-1 is tracked as a Phase-4
entry obligation, not a Phase-3 deliverable.

Phase 3 exit criteria (ROADMAP week 5–6):

- REST policy change → kernel map < 500 ms, measured end-to-end (A-3 / MER-73).
- Every pod veth attached within 100 ms, no leaked attachments (A-2 / MER-71).
- CA can mint a node cert + a workload SVID; node bootstrap credential issued
  (PKI-1/2 / MER-74/75).
