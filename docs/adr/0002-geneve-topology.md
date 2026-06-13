# ADR-0002: Geneve topology — attachment point, tunnel ownership, and node fabric

- **Status:** Accepted (Phase 1 contract freeze, MER-28)
- **Date:** 2026-06-13
- **Relates to:** ARCHITECTURE D8 (identity width / Geneve option), §1
  (TC ingress identity resolution), §1 `tc_egress` deltas, "Geneve identity
  option" (CC-3); the **open** data-path item "Geneve parse placement relative
  to kernel decap". Consumed by MER-20 (`tc_egress` option push), MER-21
  (ingress parse + P1.3 gate), MER-28 (two-node harness), MER-29 (live policy
  integration).

## Context

Phase 1 introduces the first multi-node data path: a workload on node A
connects to a workload on node B, and node B must enforce policy keyed on
node A's **identity**, not on node A's (cluster-irrelevant, possibly reused)
overlay IP. The carrier for that identity is a Geneve option (D8/CC-3:
class `MERIDIAN_GENEVE_CLASS`, type `MERIDIAN_OPT_IDENTITY`, length 1, body =
`__u32 src_identity` in network order).

Three things were left unpinned and are mutually entangled, so they are frozen
together here rather than discovered independently by MER-20, MER-21, and
MER-28:

1. **Attachment point.** The kernel Geneve device performs decapsulation in the
   kernel and **discards Geneve options** before the inner packet surfaces on
   the overlay interface. A TC program attached to the overlay device (`gnv0`)
   therefore can never see the identity option — it has already been stripped.
   So "where does `tc_ingress` parse the option" is not a free choice; it
   dictates whether the design is even possible. ARCHITECTURE lists this as
   "the biggest unresolved data-path detail."
2. **Tunnel ownership.** Who creates and owns the Geneve link, its VNI, and its
   UDP port — Meridian, or the host/CNI fabric Meridian rides on.
3. **Namespace topology + routing model.** The MER-28 harness encodes a
   specific underlay/overlay split and routing path; MER-21's gate test and
   MER-29's live test both assert against it, so it must be a contract, not an
   incidental harness detail.

Changing any of these after MER-20/MER-21 consume them would ripple through both
kernel programs, the harness, and every integration test — hence a freeze at
the Phase 1 boundary, before the consuming code exists.

## Decision

### D-A — Attachment point: the node **underlay** device, around kernel (de)cap

Both TC programs attach (via `clsact`, direct-action — MER-25 path) to the
node's **underlay / uplink** device, where packets are fully Geneve-encapsulated:

```
[ outer IP ][ UDP :6081 ][ Geneve base ][ TLV: identity ][ inner IP ][ inner L4 ]
```

- **Ingress** (`tc_ingress`, MER-21) runs **before** the kernel Geneve device
  decapsulates. It walks the outer UDP→Geneve→TLV chain in-program (the
  `#pragma unroll` walk, hard cap `MAX_GENEVE_OPTS = 4`, per-iteration bounds
  checks), recovers `src_identity` from the option, parses the **inner** IP/L4
  for `dst_ip`/`dst_port`/`proto`, resolves `dst_id` locally from
  `identity_map`, performs the policy lookup, and renders the verdict on the
  encapsulated frame. Survivors are passed to the kernel for normal decap and
  delivery; denied packets are `TC_ACT_SHOT` before decap.
- **Egress** (`tc_egress`, MER-20) runs **after** the kernel Geneve device has
  encapsulated a tunnel-bound packet. For remote destinations it **pushes** the
  identity TLV into the formed Geneve header via `bpf_skb_adjust_room`
  (MTU headroom reserved; encap-failure posture is a separate open item).
  Non-tunnel traffic is untouched.

**Rationale.** This is the only placement where the identity option is visible
to BPF: pre-decap on the way in, post-encap on the way out. It keeps identity
resolution, policy lookup, and verdict in a **single program per direction** on
a **single device**, with no need to smuggle identity across the kernel decap
boundary (per-CPU scratch, conntrack marks, or a flow side-table — all
rejected below). Same-node, non-tunnel traffic never reaches the underlay and
is enforced on the workload veth as today; the Geneve path is purely additive.

### D-B — Tunnel ownership: the **host/CNI fabric** owns the device; Meridian owns the **TLV**

Meridian does **not** create, configure, or tear down the Geneve link. The
Geneve transport — device, VNI, UDP port, base-header (de)cap — is owned by the
node's host/CNI networking layer. Meridian is a **passenger**: it owns only
(a) the identity TLV carried inside an otherwise host-managed tunnel, and
(b) the TC programs bracketing the device. The frozen transport parameters
Meridian assumes are present:

| Parameter        | Value      | Source                         |
| ---------------- | ---------- | ------------------------------ |
| Device name      | `gnv0`     | harness `geneveDeviceName`     |
| VNI              | `100`      | harness `geneveVNI`            |
| UDP dst port     | `6081`     | harness `genevePort` (IANA)    |
| Option class     | `MERIDIAN_GENEVE_CLASS` | D8/CC-3 / `meridian_consts.h` |
| Option type      | `MERIDIAN_OPT_IDENTITY` | D8/CC-3            |
| Option body      | `__u32 src_identity`, **network order**, 4 B | D8 |

In tests, the **MER-28 harness stands in for the CNI**: it creates `gnv0` with
fixed `id/remote/local/dstport` in each node namespace. Production wiring (real
CNI, flow-based/`external` Geneve, or a managed overlay) may differ in *how* the
device is created, but the contract above — and the fact that Meridian only
reads/writes the TLV — does not change.

### D-C — Namespace layout (frozen, per MER-28)

One netns per simulated node; the host root netns is the shared underlay fabric.
For `baseOctet = N`:

```
                              root netns (underlay fabric, ip_forward=1)
        172.31.N.1/30 (mha-*) ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ 172.31.N+1.1/30 (mhb-*)
                 │  veth pair                                       │  veth pair
   ┌─────────────┴──────────────┐                    ┌─────────────┴──────────────┐
   │ node-a ns                  │                    │ node-b ns                  │
   │  nva-*  172.31.N.2/30      │  underlay (routed) │  nvb-*  172.31.N+1.2/30    │
   │  gnv0   10.200.N.1/24      │◀═ VNI 100/UDP 6081═│  gnv0   10.200.N.2/24      │
   │           ▲ overlay        │                    │           ▲ overlay        │
   │     workloads bind here    │                    │     workloads bind here    │
   └────────────────────────────┘                    └────────────────────────────┘
```

- **Underlay** (`172.31.N.x/30`, one /30 per node): root↔node veth pairs; this
  is where the Geneve-encapsulated UDP flows and where the TC programs attach.
- **Overlay** (`10.200.N.x/24`): the `gnv0` addresses workloads use as source
  and destination; identity-bearing inner traffic.
- Per-run namespaced names (`RunID()` suffix) and `t.Cleanup`-driven reaping
  keep N nodes collision-free on one CI host (ARCHITECTURE §multi-node).

### D-D — Routing model (frozen, per MER-28)

- Node→node underlay reachability is via **host routes through the root
  namespace**: each node has `ip route <peer-underlay>/32 via <host-side
  underlay> dev <node-veth>`; the root netns forwards (`ip_forward=1`,
  ref-counted, original value restored on teardown). There is **no** bridge and
  **no** NAT on the underlay — pathing is deterministic and inspectable.
- Overlay reachability is **explicit `/32` host routes over `gnv0`**
  (`ip route <peer-overlay>/32 dev gnv0`), not subnet routes, so a packet's
  egress device is unambiguous for both the kernel encap step and the TC
  attach point.
- Encapsulation/decapsulation is the kernel Geneve device's job (D-B); routing
  never sees Meridian inserting or removing the base header — only the TLV.

## Rejected alternatives

1. **Attach `tc_ingress` to the overlay device (`gnv0`), post-decap.** The
   kernel strips Geneve options during decap, so `src_identity` is gone by the
   time the packet reaches `gnv0`. Unworkable for the carried-identity path;
   this is the constraint that forces D-A.
2. **Carry identity across the decap boundary** (per-CPU scratch keyed by inner
   flow, a conntrack/skb mark, or a flow side-table populated by an underlay
   program and read by an overlay program). Rejected: two programs and a
   shared-state hazard (CPU migration, flow-key collisions, table eviction) to
   reconstruct what one underlay program already has in hand. Exactly the
   silent-divergence class the reference evaluator exists to catch.
3. **Flow-based / `external` (collect_metadata) Geneve with
   `bpf_skb_get/set_tunnel_opt`.** A clean kernel-native way to read/write
   options as metadata — but it requires Meridian to **own** the tunnel device
   and its metadata-mode lifecycle, violating D-B (passenger, not fabric
   owner), and the MER-28 harness models the realistic case: a fixed,
   host-created device. Revisitable if production CNI standardizes on
   metadata-mode tunnels; the TLV contract is unchanged either way.
4. **Meridian creates and owns the Geneve link.** Rejected: duplicates CNI
   responsibility, couples Meridian to overlay addressing/MTU/lifecycle it does
   not control in production, and makes the agent's restart-safety contract
   (leave datapath state in place across restarts) responsible for tunnel
   teardown it should never perform.
5. **Encode identity in the VNI or outer addressing instead of a TLV.**
   Rejected: VNI is host/CNI-owned (D-B) and far too narrow for a cluster-global
   `__u32` identity space (D8); overloading it collides with real tenancy use.

## Consequences

- **MER-21** (`tc_ingress` Geneve parse + P1.3 gate) attaches on the **node-B
  underlay veth**, ingress direction, and reads `src_identity` from the TLV
  for flows whose source IP is not in the local `identity_map` (remote nodes
  never are). A missing option on tunnel traffic → `src_id = 0` plus the
  `GENEVE_DECODE_FAIL` counter (cross-node identity loss alert), then the
  `FALLOPEN_UNKNOWN` posture applies (separate open ADR). The gate asserts both
  an allow and a deny case keyed on the decoded remote identity.
- **MER-20** (`tc_egress` + option push) attaches on the **underlay egress**
  and pushes the TLV with `bpf_skb_adjust_room` **after** kernel encap, at the
  point this ADR fixes; T2 asserts the rewritten bytes carry the option with
  the correct class/type/body and that non-tunnel traffic is untouched. For
  remote destinations `dst_id` is locally unknown (`0`) — enforcement is
  destination-node-authoritative (the open egress-policy ADR is unaffected by
  this topology freeze).
- **MER-28 / MER-29** treat the namespace layout (D-C) and routing model (D-D)
  as a contract: `AssertAllowed`/`AssertDenied` and the live policy test bind to
  the overlay `10.200.N.x` addresses while enforcement happens on the
  `172.31.N.x` underlay attach point.
- **Out of scope here** (each its own open ADR): unknown-identity posture
  (`FALLOPEN_UNKNOWN`), egress encap-failure policy (drop vs pass-unencapsulated),
  and MTU/headroom accounting for the pushed option. This ADR fixes *where* and
  *who*, not those *what-on-failure* questions.
