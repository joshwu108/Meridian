# ADR-0008: Compiled-policy + xDS resource wire contract (CC-2)

- **Status:** Accepted (Phase-3 control-plane↔agent transport contract; MER-70)
- **Revised:** 2026-06-18 (MER-77) — §2 encoding changed from protoc-generated
  messages to a **no-protoc, versioned JSON** payload. The build environment has no
  `protoc`/`protoc-gen-go`/`buf` (host or Lima 5.15), and a protoc build dependency
  cuts against D11 (minimal deps). §1 (type_url mapping) and §3 (commit ordering)
  are unchanged. **Reversible:** if a protoc toolchain is provisioned (host + Lima +
  CI) later, a follow-up revision may move §2 back to generated protos without
  touching §1/§3.
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

Each resource is a `google.protobuf.Any` wrapping a `google.protobuf.BytesValue`
whose `.value` is a **versioned JSON document** — the frozen CC-2 encoding. JSON
(stdlib `encoding/json`) is chosen over protoc-generated messages because the
build environment has no protoc toolchain (host or Lima) and a protoc dependency
is disproportionate for two flat structs (D11); the contract is made rigorous by
**freezing the schema, versioning it, and validating field widths** rather than by
codegen. The payload is single-sourced with `pkg/wire` and mirrors the ADR-0004
frozen kernel structs field-for-field.

**Envelope (every resource):**

```json
{ "schema_version": 1, "kind": "PolicyRule" | "Identity", "spec": { … } }
```

`schema_version` is a `uint32` (currently **1**); a decoder MUST reject an unknown
major version (→ NACK). `kind` MUST match the channel (CDS→`PolicyRule`,
EDS→`Identity`); a mismatch is a contract violation (→ NACK).

**`PolicyRule` spec (CDS) — mirrors `wire.PolicyRule`:**

```json
{ "src_identity": <u32>, "dst_identity": <u32>, "dst_port": <u16>,
  "protocol": <u8>, "direction": <0|1>,
  "action": <0|1|2>, "flags": <u8 POLICY_FLAG_* bitset> }
```

**`Identity` spec (EDS) — mirrors `wire.Identity`:**

```json
{ "id": <u32, 0 reserved (CC-3)>, "spiffe_id": <string>,
  "pod_ipv4": <string>, "namespace": <string>, "name": <string> }
```

**Decode rules (fail-closed):**

1. Decode with `json.Decoder` + **`DisallowUnknownFields`** and reject trailing
   data — an unknown field or junk is a contract violation (→ NACK), so a typo or a
   future field a stale agent can't model never silently drops to a default.
2. **Integer-width validation:** `dst_port` ≤ 65535, `protocol`/`flags` ≤ 255,
   `direction` ∈ {0,1}, `action` ∈ {0,1,2}, identities are `uint32`; out-of-range
   → NACK (mirrors the ADR-0004 kernel widths exactly).
3. **Evolution is additive + version-gated:** new optional fields require a
   `schema_version` bump and remain backward-compatible at the prior version;
   existing field names/types/semantics never change. Removing or repurposing a
   field requires a new major `schema_version` (and a new ADR revision).

This **supersedes** the D21 interim encoding by *freezing and versioning* it — the
interim shipped an unversioned, schema-free `[]wire.PolicyRule` JSON blob on the
Cluster channel only; the frozen contract adds the version/kind envelope, the
identity (EDS) channel, `DisallowUnknownFields`, and explicit width validation.

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
the generated `bpf/` types (ARCHITECTURE D17); the decoded resource payloads
become `wire` types, which `datapath` translates to kernel structs. The ADS client
(`internal/agent/xds`) never touches `bpf/` (depguard).

## Rejected alternatives

- **Keep the interim encoding exactly as-is (D21).** Rejected: it is an
  *unversioned, schema-free* `[]wire.PolicyRule` JSON blob on the Cluster channel
  only, with no identity channel and no decode validation — it cannot express the
  identity-before-policy commit ordering A-3 needs and silently tolerates drift.
  This ADR keeps JSON but **freezes + versions** it (envelope, `schema_version`,
  EDS channel, `DisallowUnknownFields`, width validation).
- **protoc-generated `meridian.config.v1` messages** (the original ADR-0008 §2).
  Rejected (MER-77): the build environment has **no protoc/protoc-gen-go/buf**
  (host or Lima 5.15), protoc is not a `go install` tool, and a protoc build
  dependency is disproportionate for two flat structs (D11). Versioned JSON over
  the stdlib meets the contract goals without codegen. **Reversible** if protoc is
  later provisioned.
- **Reuse envoy `Cluster`/`ClusterLoadAssignment` protos to carry Meridian
  semantics.** Rejected: Meridian's identity-keyed L4 policy has no faithful
  mapping onto envoy's upstream-cluster/endpoint/LB model; the impedance mismatch
  is lossy and misleading. The Meridian payload stays single-sourced with
  `pkg/wire` and the ADR-0004 kernel structs.
- **A custom non-xDS gRPC streaming protocol.** Rejected: would discard the
  version/nonce ACK/NACK state machine, make-before-break ordering, and the
  go-control-plane tooling already built and gated in MER-54/56.

## Consequences

- MER-72 (A-3) implements the versioned-JSON codec (encode/decode for the §2
  envelope + specs), swaps the MER-54 server resource builder and the MER-55 stub
  decode from the unversioned interim blob onto it, and implements the agent
  decode + commit-ordered translation. The version/nonce transport is untouched;
  MER-56 (CP-3) conformance should stay green after the swap (the encode/decode
  changes, not the handshake). No protoc / generated bindings are introduced.
- The interim encoding (D21) is **superseded by this ADR** the moment MER-72 lands
  the versioned codec; until then D21 remains the as-built note and this ADR is the
  target.
- LDS/RDS L7 resources are deferred to Phase 5; reserving them now keeps the
  channel mapping stable so L7 lands additively without re-freezing CC-2.
