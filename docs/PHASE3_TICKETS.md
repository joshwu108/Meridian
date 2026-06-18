# Phase 3 Tickets — Agent Lifecycle + ADS Client + PKI Primitives

Decomposition of the Phase-3 scope ([PHASE3_PLAN.md](PHASE3_PLAN.md)) into
ticket-sized units. IDs **MER-70 … MER-76** are reserved here; `tickets.md`
`Next free ID` advances to **MER-77**. Gates are defined in
[PHASE3_GATES.md](PHASE3_GATES.md).

Entry gate: **MER-59 green** (Phase-2 exit) — satisfied. Implementation tickets
(MER-71+) may merge; planning (MER-69) and the CC-2 ADR (MER-70) have no entry
dependency.

| ID | Title | Lane | Est | Scope (one-line) | Deps | Files (expected) |
|----|-------|------|-----|------------------|------|------------------|
| **MER-70** | **CC-2 ADR — compiled-policy + xDS resource wire contract** | Platform | 2–3h | Author `docs/adr/0008-xds-wire-contract.md`: the frozen `type_url`→Meridian mapping (CDS=policy/cluster, EDS=identity/endpoint, LDS/RDS=L7), the resource message shape, and how it **supersedes** the MER-54 interim `[]wire.PolicyRule`-in-`BytesValue` encoding (D21/MER-67). Decision-log entry; ADR index + numbering-gap check. No code. | MER-54 ✅, D21 | `docs/adr/0008-xds-wire-contract.md`, `docs/adr/README.md`, `docs/ARCHITECTURE.md` |
| **MER-71** | **A-2 — agent netlink veth lifecycle** | Agent | 4–5h | `internal/agent/linkwatch`: `RTMGRP_LINK` watcher + **full interface reconcile before subscribe**; auto attach/detach TC programs on veth appear/remove via the `attach` managers; idempotent; survives ENOBUFS (resubscribe + reconcile). | MER-57 ✅ (attach), A-1 ✅ | `internal/agent/linkwatch/*.go`, `internal/agent/supervisor/*.go` (wire-in) |
| **MER-72** | **A-3 — ADS client + xDS→CommitPlan translation** | Agent | 5–6h | `internal/agent/xds` ADS client (single bidi stream to `meridian-control`, ACK-after-apply, NACK-holds-last-good) + `internal/agent/datapath` translation to `identity_map`/`policy_map` with safe write ordering (identities before policies; remove-allow before add on shrink). Replaces the MER-55 stub agent-side; decodes the **CC-2** contract. | MER-70, MER-54 ✅ | `internal/agent/xds/*.go`, `internal/agent/datapath/*.go` |
| **MER-73** | **A-3 GATE — REST→kernel < 500 ms end-to-end (Phase-3 exit gate)** | Agent | 3–4h | T3 integration: REST `POST /policies` → control plane → ADS → agent → **kernel `policy_map`** reflects the rule in < 500 ms (`WaitUntil`, not sleep); NACK on malformed resource holds last-good; no transient over-permit on shrink. Arms a manifest gate row. | MER-71, MER-72 | `test/integration/rest_to_kernel_test.go`, `test/gates/manifest.txt` |
| **MER-74** | **PKI-1 — CA primitives** | PKI | 4–5h | `internal/control/ca` (or `internal/pki`): offline-style self-signed Root (test fixture) → in-process Intermediate (ECDSA P-384); CSR validation (P-256 workload keys, single `spiffe://` URI SAN, node-authorized-for-identity vs the registry); SVID signing (24h TTL); typed fail-closed errors. Unit-tested against a local test CA (no `go-spiffe` runtime dep yet). | MER-53 ✅ (identity registry) | `internal/control/ca/*.go`, `*_test.go` |
| **MER-75** | **PKI-2 — node bootstrap credential (CC-4)** | PKI | 3–4h | Two-tier credential: a node identity (7d) distinct from workload SVIDs (24h), authenticating the agent↔control channel. **Standalone mode**: operator-provisioned `bootstrap.crt`/`.key`, node SPIFFE ID `spiffe://cluster.local/node/<id>`. (K8s projected-token + `TokenReview` path deferred to Phase 7.) | MER-74 | `internal/control/ca/bootstrap*.go`, `cmd/meridian-agent` config wire-in, `*_test.go` |
| **MER-76** | **Phase-3 EXIT — doc reconciliation + Phase-4 entry rule** | all (review) | 2h | PHASE3_GATES all green with evidence; README/ROADMAP updated to Phase-3 complete; ARCHITECTURE as-built (CC-2 frozen, A-2/A-3 pipeline, PKI hierarchy); state the **Phase-4 entry rule = CC-1 echo prototype (ADR-0006) passes** before any Phase-4 (proxy/TLS) work. | MER-73, MER-74, MER-75 | `docs/PHASE3_GATES.md`, `README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md` |

---

## Dependency graph / schedule

```text
[ENTRY] MER-59 green (Phase-2 exit) — SATISFIED

Wave 0: MER-70 (CC-2 ADR)  ∥  MER-71 (A-2)  ∥  MER-74 (PKI-1)
Agent:  MER-71 → MER-73* ;  MER-70 → MER-72 → MER-73*
PKI:    MER-74 → MER-75
EXIT:   MER-76 ← {73*, 74, 75}

Joins: MER-72 ← {70, 54✅} · MER-73 ← {71, 72} · MER-75 ← {74}
*MER-73 = Phase-3 exit gate (REST→kernel < 500 ms)
```

- **Critical path:** MER-70 → MER-72 → MER-73 → MER-76.
- **Gates:** A-2 (MER-71, veth-attach < 100 ms / no-leak) · **A-3 = MER-73**
  (REST→kernel < 500 ms, the exit-criterion gate) · PKI-1 unit gate (MER-74).
- **Phase 3 → 4 entry:** CC-1 echo prototype (ADR-0006) — tracked in Phase 4, not
  here; Phase-4 implementation may not start until it passes.

`Next free ID` after this batch: **MER-77**.
