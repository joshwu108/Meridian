# Phase 3 Work Breakdown — Agent Lifecycle + ADS Client + PKI Primitives

Scope (ROADMAP week 5–6, PRD phase 3): the node agent grows from the Phase-1
stub into a live daemon — netlink-driven veth lifecycle (**A-2**) and a real ADS
client that translates xDS into kernel map writes (**A-3**) — while the PKI
subsystem stands up its CA primitives (**PKI-1**) and the node bootstrap
credential (**PKI-2**). Exit: **REST policy change lands in the kernel map
< 500 ms end-to-end** (PRD success criterion #4, measured for real — the Phase-2
CP-3 gate measured REST→stub; Phase 3 measures REST→**kernel**).

Carry-in from Phase 2: the ADS server with version/nonce state machine + ordered
push (MER-54), the in-memory agent stub A-3 replaces (MER-55), the CP-3
conformance gate (MER-56), `control.Store` + identity registry + REST (MER-53),
the agent SOCKMAP attach + `bpfobj` pin re-open path (MER-57/58), and the frozen
v2 map schemas (ADR-0004). The MER-54 ADS resource encoding is an **interim**
placeholder (D21/MER-67) that the CC-2 ADR (MER-70) freezes this phase.

Owner roles (one person may hold several):

| Role | Profile |
|---|---|
| **Agent** | Go systems: `vishvananda/netlink` watcher, ADS gRPC client, xDS→`CommitPlan` translation, kernel map writes via `datapath` |
| **PKI** | Go crypto: `crypto/x509`/`ecdsa` CA hierarchy, CSR validation, node bootstrap credential |
| **Platform** | Pure-Go: the CC-2 wire-contract ADR + any control-plane resource-encoding changes it implies |

---

## 0. Phase-3 entry gate (hard sequencing rule)

**No Phase-3 implementation ticket (MER-71+) may merge until MER-59 (Phase-2
exit) is green AND the ADR-0004 frozen map schemas are unchanged.** MER-59 is
green at HEAD (`d8c7612`, finalized by MER-68 deterministic gate harness), so the
entry gate is satisfied.

Phase-3 **planning** (this document, [PHASE3_TICKETS.md](PHASE3_TICKETS.md),
[PHASE3_GATES.md](PHASE3_GATES.md)) has no dependency and lands now (MER-69),
mirroring how MER-46 planned Phase 2 while Phase-1 gates were still open.

The **CC-2 wire-contract ADR (MER-70)** is a soft prerequisite for A-3 (MER-72):
A-3's translation must target the frozen contract, not the MER-54 interim
JSON-in-`BytesValue` encoding. MER-70 should land before MER-72 completes.

---

## 1. Architecture updates (land via MER-70 / MER-72 / MER-76)

Deltas to `docs/ARCHITECTURE.md`; the decision log continues from D21.

- **CC-2 freeze (MER-70).** The compiled-policy + xDS resource wire contract:
  which xDS `type_url` carries which Meridian construct, the resource message
  shape (supersedes the interim `[]wire.PolicyRule`-in-`BytesValue` on the
  Cluster channel, D21), and the EDS-identity / CDS-policy / LDS-RDS-L7 mapping.
  Recorded as a numbered ADR + a decision-log entry; A-3 and any control-plane
  resource-builder change depend on it.
- **xDS apply pipeline as-built (MER-72).** The ARCHITECTURE "xDS apply pipeline"
  (RECEIVE → VALIDATE → TRANSLATE → STAGE → COMMIT → ACK) becomes real code in
  the agent: `internal/agent/xds` (ADS client) + `internal/agent/datapath`
  (the sole `wire`↔`bpf` translator, D17) writing `identity_map`/`policy_map`.
- **Netlink lifecycle as-built (MER-71).** `internal/agent/linkwatch`:
  `RTMGRP_LINK` subscription + a full interface reconcile **before** subscribing
  (closes the missed-event race, ARCHITECTURE lifecycle FSM).
- **PKI hierarchy (MER-74/75).** Root (offline, self-signed) → in-process
  intermediate (P-384) in `meridian-control`; node bootstrap credential (CC-4)
  is the two-tier scheme (node identity vs workload SVID); standalone mode uses
  an operator-provisioned `bootstrap.crt`/`.key` (K8s TokenReview deferred to
  Phase 7).

---

## 2. Workstreams & dependency graph

```text
[ENTRY] Phase-3 entry = MER-59 green (Phase-2 exit) — SATISFIED

Wave 0 (foundational): MER-70 (CC-2 ADR)  ∥  MER-71 (A-2 netlink, no CC-2 dep)
Lane Agent:    MER-71 (A-2) → MER-73 (A-3 gate)
               MER-70 (CC-2) → MER-72 (A-3 client/translate) → MER-73 (A-3 gate)
Lane PKI:      MER-74 (PKI-1 CA) → MER-75 (PKI-2 node bootstrap, CC-4)
Join (EXIT):   MER-76 ← {73 (REST→kernel <500ms), 74, 75}

Joins: MER-72 ← {70, 54✅} · MER-73 ← {71, 72} · MER-75 ← {74}
```

- **Critical path:** MER-70 → MER-72 → MER-73 (the REST→kernel <500 ms exit gate).
  A-2 (MER-71) is on the path to MER-73 (the gate needs live veth attach) but can
  build in parallel with the CC-2/A-3 chain.
- **PKI lane (MER-74/75) runs off the critical path** — buildable against a local
  test CA and a `go-spiffe` fake; its on-path obligation is only the node
  bootstrap credential the Phase-4 mTLS work will consume.
- **Phase 3 → 4 entry** (per ROADMAP) is the **CC-1 echo prototype (ADR-0006)** —
  out of Phase-3 scope; Phase 4 may not start until that no-TLS redirect proof
  passes.

---

## 3. Top risks (Phase 3)

| # | Risk | Likelihood / Impact | Mitigation |
|---|---|---|---|
| 1 | **Translation divergence** — xDS→`CommitPlan` writes that transiently widen allows, or identity-before-policy ordering violated | Med / High | D17 single translator + property tests vs the reference evaluator; write ordering: identities before policies, remove-allow before add on shrink; the MER-73 gate asserts no transient over-permit |
| 2 | **Restart / missed netlink events** leave veths unattached | Med / High | Full interface reconcile before subscribe (A-2); chaos test: churn netns+veth, assert every veth attached < 100 ms, no leaks |
| 3 | **CC-2 contract churn** — A-3 built against the interim encoding then reworked | Med / Med | Land MER-70 (CC-2 ADR) before MER-72 completes; A-3 targets the frozen contract |
| 4 | **REST→kernel > 500 ms** under load | Low / High | Measure early with `WaitUntil` (not sleep); ACK only after commit so the metric measures truth; decoupled latest-wins apply channel |
| 5 | **Bootstrap circularity** (agent needs identity to get identity) | Low / High | Two-tier credential (CC-4): node identity authenticates the channel; standalone operator-provisioned cert in Phase 3, K8s TokenReview in Phase 7 |

---

## 4. Staffing variants

One engineer can carry the Agent lane (MER-71→72→73) sequentially while the PKI
lane (MER-74→75) and the CC-2 ADR (MER-70) interleave; two engineers split
Agent vs PKI with MER-70 owned by whoever holds Platform. The MER-73 gate is the
serialization point — it needs A-2 + A-3 both green.
