# ADR-0008: Compiled-policy + xDS resource wire contract (CC-2)

- **Status:** Accepted (Phase-3 control-plane↔agent transport contract; MER-70)
- **Date:** 2026-06-17
- **Relates to:** ROADMAP [CC-2](../../ROADMAP.md#cross-cutting-decisions)
  ("the byte layout … and the xDS metadata schema carrying verdicts,
  `l7_required`, identity IDs, and L7 rules is *the* contract … freeze before
  Phase 3 completes"); [ADR-0004](0004-map-schema-freeze.md) (the **kernel half**
  of CC-2 — frozen `policy_key`/`policy_verdict`/`identity` structs);
  ARCHITECTURE **D21** (the MER-54 interim encoding this supersedes) and the
  "xDS apply pipeline"; [PHASE3_TICKETS](../PHASE3_TICKETS.md) MER-72 (A-3, the
  consumer) and MER-73 (the REST→kernel < 500 ms gate). Supersedes the interim
  payload recorded in **D21 / MER-67**.

## Context

CC-2 is the cross-boundary contract between control plane, agent, and kernel.
Its **kernel half is already frozen** (ADR-0004: `policy_key` with the explicit
direction byte, `policy_verdict.flags`, the `identity` struct, schema v2). What
is *not* yet frozen is the **transport half**: how the control plane carries
compiled policy and identity state to the agent over the ADS stream, and how the
agent translates it into `identity_map` / `policy_map` writes.

Phase 2 shipped an explicitly **interim** encoding (D21/MER-67): the MER-54 ADS
server packs a JSON-marshalled `[]wire.PolicyRule` inside a
`google.protobuf.BytesValue` `Any` on the Cluster channel only, with the other
channels versioned-but-empty. That was a private server↔stub contract sufficient
for the CP-1/CP-3 gates — **not** a frozen wire contract, and the D21 entry says
so. Phase-3 A-3 (MER-72) makes the agent translate real xDS into the kernel; it
must compile against a frozen contract, not the placeholder. This ADR freezes it.

The ADS **transport** mechanics — the per-`(stream, type_url)` version/nonce
handshake, ACK-advances / NACK-holds-last-good (CC-5 fail-closed), and the
`Store.Watch()`-driven make-before-break push — are already decided (D21, MER-54)
and are **not** re-opened here. This ADR fixes only the *resource payload* and the
*apply ordering*.

## Decision

### 1. type_url → Meridian construct mapping

The DiscoveryResponse `type_url` uses the standard envoy xDS resource types (so
the stream subscription, version/nonce bookkeeping, and CDS→EDS / LDS→RDS
make-before-break ordering from MER-54 are unchanged). Each channel carries a
**Meridian-native** resource (see §2), not envoy semantics:

| xDS channel (`type_url`) | Carries | Meridian source type | Kernel target |
|---|---|---|---|
| **CDS** (`…v3.Cluster`) | compiled L4 policy rules | `wire.PolicyRule` (`wire.PolicySnapshot.Policies`) | `policy_map` |
| **EDS** (`…v3.ClusterLoadAssignment`) | identity ↔ endpoint metadata | `wire.Identity` (`wire.PolicySnapshot.Identities`) | `identity_map` |
| **LDS** (`…v3.Listener`) / **RDS** (`…v3.RouteConfiguration`) | L7 rules | (Phase-5 `l7_*`) | node proxy snapshot |

Policy rides the **Cluster (CDS)** channel — continuous with the shipped MER-54
mapping. LDS/RDS are **reserved and versioned-but-empty** until Phase 5 (L7); the
agent must tolerate empty L7 channels without NACK.

### 2. Resource message shape

Each resource is a `google.protobuf.Any` wrapping a **Meridian-defined protobuf
message** (not JSON-in-`BytesValue`, not an envoy proto) carried over the xDS
transport. The messages are single-sourced with `pkg/wire` and mirror the
ADR-0004 frozen kernel structs field-for-field. The `.proto` is authored in
MER-72; the **frozen field set + numbers** are:

```proto
// package meridian.config.v1;  type_url prefix: type.meridian.io/

message PolicyRule {           // CDS resource — mirrors wire.PolicyRule
  message Key {
    uint32 src_identity = 1;   // wire.IdentityID
    uint32 dst_identity = 2;
    uint32 dst_port     = 3;   // uint16 range
    uint32 protocol     = 4;   // uint8 range (IPPROTO_*)
    uint32 direction    = 5;   // 0=ingress, 1=egress (ADR-0003)
  }
  Key    key     = 1;
  uint32 action  = 2;          // 0=allow,1=deny,2=redirect_proxy
  uint32 flags   = 3;          // POLICY_FLAG_* bitset (ADR-0004 D4)
}

message Identity {             // EDS resource — mirrors wire.Identity
  uint32 id        = 1;        // wire.IdentityID; 0 reserved (CC-3)
  string spiffe_id = 2;
  string pod_ipv4  = 3;
  string namespace = 4;
  string name      = 5;
}
```

Field numbers are **frozen**: new fields append; existing numbers/types never
change (proto3 evolution). Integer-range fields (`dst_port`, `protocol`,
`action`, `flags`, `direction`) are validated against their kernel widths on
decode; an out-of-range value is a contract violation → NACK.

### 3. Apply (write) ordering — kernel commit contract

**Transport push order** is the xDS make-before-break convention (CDS→EDS,
LDS→RDS), unchanged from MER-54. **Kernel commit order is independent and is
fixed here**: the agent buffers a full snapshot (latest-wins) and applies it in
the ARCHITECTURE "xDS apply pipeline" phase order, never widening transiently:

1. **identity adds/updates** (`identity_map`) — *before* any policy that
   references them, so no policy keys a not-yet-present identity;
2. **policy adds/updates** (`policy_map`);
3. **policy removes** — on a shrink, an allow is removed **before** a narrower
   allow/deny is added (never a transient widen);
4. **identity deletes** — last, after no policy references them.

The agent **ACKs only after the commit succeeds** (so
`meridian_policy_propagation_seconds` and the MER-73 < 500 ms gate measure truth).
A mid-apply error rolls back to the prior byte-identical kernel state and NACKs
(holds last-known-good — CC-5). A decode/range/contract violation NACKs with
`error_detail` and never partially applies.

### 4. Translation boundary

`internal/agent/datapath` remains the **sole** importer of both `pkg/wire` and
the generated `bpf/` types (ARCHITECTURE D17); the xDS resource protos decode to
`wire` types, which `datapath` translates to kernel structs. The ADS client
(`internal/agent/xds`) never touches `bpf/` (depguard).

## Rejected alternatives

- **Keep the interim JSON-in-`BytesValue` (D21).** Rejected: not language-neutral
  or schema-evolvable, no field-level versioning, opaque to proto tooling, and
  carries policy on one channel with no identity channel — it cannot express the
  identity-before-policy commit ordering A-3 needs.
- **Reuse envoy `Cluster`/`ClusterLoadAssignment` protos to carry Meridian
  semantics.** Rejected: Meridian's identity-keyed L4 policy has no faithful
  mapping onto envoy's upstream-cluster/endpoint/LB model; the impedance mismatch
  is lossy and misleading. Meridian protos stay single-sourced with `pkg/wire`
  and the ADR-0004 kernel structs.
- **A custom non-xDS gRPC streaming protocol.** Rejected: would discard the
  version/nonce ACK/NACK state machine, make-before-break ordering, and the
  go-control-plane tooling already built and gated in MER-54/56.

## Consequences

- MER-72 (A-3) authors the `meridian.config.v1` `.proto`, swaps the MER-54 server
  resource builder from JSON-in-`BytesValue` to these protos, and implements the
  agent decode + commit-ordered translation. The version/nonce transport is
  untouched; MER-56 (CP-3) conformance should stay green after the swap (the
  stub/agent decode changes, not the handshake).
- The interim encoding (D21) is **superseded by this ADR** the moment MER-72 lands
  the proto path; until then D21 remains the as-built note and this ADR is the
  target.
- LDS/RDS L7 resources are deferred to Phase 5; reserving them now keeps the
  channel mapping stable so L7 lands additively without re-freezing CC-2.
