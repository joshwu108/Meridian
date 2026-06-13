# ADR-0005: Geneve encapsulation failure policy

- **Status:** Accepted (Phase 1 — resolves the "egress encap-failure policy
  (drop vs pass-unencapsulated)" item explicitly deferred by ADR-0002
  §Consequences / §Out of scope)
- **Date:** 2026-06-13
- **Relates to:** [ADR-0001](0001-unknown-identity-posture.md) (unknown-identity
  posture + `MERIDIAN_CFG_FALLOPEN_UNKNOWN`), [ADR-0002](0002-geneve-topology.md)
  (D-A attachment point, D-B passenger/TLV ownership), ARCHITECTURE D8/CC-3
  (identity TLV), D16 (`runtime_config_map`). Consumed by MER-20 (`tc_egress`
  option push), MER-21 (ingress decode), MER-28/MER-29 (two-node + live tests).

## Context

ADR-0002 fixed *where* and *who*: on the way out, `tc_egress` (MER-20) attaches
to the node **underlay** device and pushes the Meridian identity TLV — class
`MERIDIAN_GENEVE_CLASS`, type `MERIDIAN_OPT_IDENTITY`, 4-byte
`src_identity` body — into the already-kernel-encapsulated Geneve frame via
`bpf_skb_adjust_room`. ADR-0002 deliberately left **one** question open and
flagged it as its own ADR: what does the egress program do when that push
**fails**?

The push can fail for several reasons, all of which surface in-datapath at the
TC hook:

- `bpf_skb_adjust_room` returns nonzero — insufficient headroom or the result
  would exceed the path MTU.
- The post-adjust bounds check against `data_end` fails (the TLV cannot be
  written within the verified packet extent).
- The packet routed to the tunnel device carries a malformed or absent Geneve
  base header, so there is no valid option region to extend.
- Adding the option would exceed the Geneve `opt_len` limit / `MAX_GENEVE_OPTS`
  (4) cap.

This matters because the TLV is the **only** carrier of source identity across
nodes (ADR-0002 §Context). A packet that egresses **without** it arrives at the
peer as identity-less tunnel traffic: per ADR-0002 §Consequences, node B sees a
missing option, sets `src_id = 0`, raises `GENEVE_DECODE_FAIL`, and falls into
the unknown-identity posture (ADR-0001). So the egress failure decision is not
local — it determines whether an **unattributable** flow is allowed onto the
cluster fabric at all, and it must compose cleanly with the receiver-side
posture rather than contradict it.

Like ADR-0001, this is a posture decision that two independent code paths (the
egress stamp and the ingress decode) must agree on, or the reference-equivalence
harness will surface the drift. It must be frozen before MER-20 consumes it.

## Problem Statement

When `tc_egress` cannot stamp `src_identity` onto a tunnel-bound packet, it must
still return a single, well-defined verdict. The candidate behaviors are:

- **Drop** the packet (`TC_ACT_SHOT`) — fail-closed at the source.
- **Pass without the TLV** — let the kernel-encapsulated frame egress carrying
  no identity, delegating the verdict to the receiver's posture. (Note: the
  inner packet is *still* Geneve-encapsulated by the kernel device per ADR-0002
  D-B; "pass unencapsulated" here precisely means "pass **without the Meridian
  identity option**," not "pass as plaintext.")
- **Retry** the stamp in-datapath.
- Some **fallback** (software re-encap, queue-for-later, side-channel the
  identity).

The decision must also fix: (1) the default posture and its override, (2)
whether egress reuses the existing unknown-identity flag or introduces a second
one, and (3) the observability contract so an operator can tell an encap failure
apart from an ordinary policy deny.

## Decision

The Geneve encapsulation-failure posture is **frozen** as follows.

### D-A — Default: DROP at egress, fail-closed

When the identity TLV cannot be pushed, `tc_egress` returns `TC_ACT_SHOT`. The
packet does not leave the node. This mirrors ADR-0001's central principle —
**absence of established identity means absence of trust** — applied to the
egress direction: an identity-less packet is never emitted onto the fabric by
default.

On the drop, the program (per MER-20):

- upserts `denied_flows_map` with the inner-flow `flow_key` and
  `deny_info.reason = DROP_REASON_GENEVE_ENCAP_FAIL` (a new value in the
  reserved range of `enum drop_reason`; filling a reserved `drop_reason` is a
  compatible change and needs **no** schema bump, per the `meridian_types.h`
  versioning rule), and
- emits a single `flow_event` with `verdict = FLOW_VERDICT_DENY` so the drop
  appears in the standard deny path, and
- increments a dedicated counter `METRIC_GENEVE_ENCAP_FAIL` (assigned from the
  reserved `metric_id` slots `6..15`, so no map resize and no pin
  invalidation).

### D-B — Optional: pass without the TLV when `FALLOPEN_UNKNOWN` is set

When bit 0 of `runtime_config_map[0]` — the **same**
`MERIDIAN_CFG_FALLOPEN_UNKNOWN` flag ADR-0001 defines — is set, `tc_egress`
returns `TC_ACT_OK`, letting the kernel-encapsulated frame egress **without**
the identity option. The verdict for that flow is then delegated to the
receiving node's unknown-identity posture (which, under its own default, denies
it — see D-D).

Egress encap-failure and ingress unknown-identity are the **same class** —
"identity could not be established for this flow" — and therefore share **one**
posture surface and **one** runtime bit. This is the direct application of
ADR-0001 Alternative #4 ("folding parse failure into the unknown-identity
posture keeps one decision point and one flag"): a second flag would be a second
surface that can drift.

`METRIC_GENEVE_ENCAP_FAIL` is incremented **regardless of posture** — including
when the flag passes the packet through. The failure condition must always be
observable; fail-open suppresses the drop, never the signal.

### D-C — No in-datapath retry; retry is L4's job

`tc_egress` does **not** retry the stamp. The dominant failure modes
(headroom / MTU, malformed base header) are deterministic for a given packet —
an in-hook retry would re-fail and burn cycles, and the TC hook has no useful
requeue primitive. Under the D-A default the dropped TCP segment is retransmitted
by the transport once the transient condition clears (e.g. PMTU re-learned),
i.e. retry happens at the **correct layer**. UDP reliability remains the
application's responsibility, unchanged by Meridian.

### D-D — Composition with ADR-0001 (defense in depth)

End-to-end, a flow is allowed identity-less only if **both** the source node is
egress-fail-open (D-B) **and** the destination node is ingress-fail-open
(ADR-0001 D-B). Under the shipped defaults — both fail-closed — an encap failure
is denied at the source; even if the source is opened, the receiver denies by
default. The two postures are independent layers, not a single point of trust.

Dropping at the source by default (rather than relying solely on the receiver's
default-deny) is deliberate: it (1) does not depend on the peer being correctly
configured, (2) does not spend fabric bandwidth on a packet that will be
dropped anyway, (3) records the failure **at the node where it actually
happened**, with the precise `DROP_REASON_GENEVE_ENCAP_FAIL`, instead of
surfacing as a confusing `unknown-identity` deny on the peer, and (4) keeps an
identity-less frame off the wire entirely.

## Alternatives Considered

1. **Pass-without-TLV by default; drop as the opt-in.** Rejected for the same
   reason ADR-0001 rejected default fail-open: it makes the safe posture the one
   an operator must remember to enable, and a zeroed/forgotten
   `runtime_config_map` would silently emit unattributable traffic that a
   fail-open peer would then accept — a cluster-scale enforcement bypass and an
   attacker primitive (induce encap failure at the MTU boundary to shed
   identity). Absence of config must mean absence of trust.

2. **A separate `MERIDIAN_CFG_FALLOPEN_ENCAP` flag, distinct from
   `FALLOPEN_UNKNOWN`.** Rejected: two posture surfaces for the same
   "identity-not-established" class can drift (egress opened, ingress closed, or
   vice versa) — exactly the silent-divergence ADR-0001 Alternative #4 warns
   against. One class, one bit.

3. **Retry the stamp in the datapath** (loop, or mark-and-recirculate).
   Rejected: deterministic failures re-fail; the TC hook cannot block or
   usefully requeue a single packet; and recirculation risks reorder/HOL
   blocking. Fail-closed delegates retry to L4 retransmission (D-C), which is
   where it belongs.

4. **Software fallback re-encap in BPF** (reconstruct the Geneve header /
   option ourselves when the kernel path lacks room). Rejected: ADR-0002 D-B
   makes Meridian a **passenger** that owns only the TLV, never the tunnel
   transport. Reimplementing encap in BPF duplicates the kernel device, couples
   Meridian to MTU/lifecycle it does not control, and reintroduces the
   cross-boundary state hazards ADR-0002 Alternative #2 rejected.

5. **Queue / redirect the packet to userspace for stamping** (XDP redirect or a
   ring to the agent). Rejected: adds latency, reordering, and head-of-line
   blocking on the hot path, and userspace cannot reliably re-stamp a frame the
   kernel has already encapsulated and handed on. The agent's restart-safety
   contract should not own per-packet buffering.

6. **Compile-time / load-time constant for the posture.** Rejected, identically
   to ADR-0001 Alternative #5: changing posture must not require recompiling and
   reattaching the BPF programs. A live-flippable `runtime_config_map` bit is the
   only option compatible with the restart-safety / no-teardown requirement.

## Security Implications

- **Deny-by-omission on the egress side too.** Any unconfigured/zeroed
  `runtime_config_map` yields fail-closed at the stamp, matching the ingress
  guarantee. There is no state in which forgetting to configure results in
  emitting identity-less traffic.
- **Encap failure cannot be turned into a bypass.** An attacker who can induce
  push failure (e.g. crafting packets at the MTU boundary) gets a drop, not an
  identity-stripped passthrough, under the default.
- **No info-leak of unattributable frames.** The default keeps identity-less
  packets off the fabric entirely, rather than relying on the peer to discard
  them after they have traversed the network.
- **`FALLOPEN_UNKNOWN` now also opens the encap-failure class.** Operators must
  understand the flag's widened blast radius: enabling it for ingress
  bootstrap/debug *also* permits identity-less egress. It remains a privileged,
  audited, time-boxed control that SHOULD alert while set (ADR-0001 §Operational
  Implications).

## Operational Implications

- **The encap-fail signal is always present.** `METRIC_GENEVE_ENCAP_FAIL`
  increments under both postures (D-B), so "are we shedding identity on egress?"
  is answerable even when fail-open hides the drops.
- **Failure is recorded where it happens.** Under the default, the source node's
  `denied_flows_map` carries the flow with `DROP_REASON_GENEVE_ENCAP_FAIL` and a
  DENY `flow_event` — distinct from a policy deny — so "traffic to node B died"
  is diagnosed at node A, not mis-attributed to an unknown-identity deny on
  node B.
- **Cross-node correlation.** Operators should correlate egress
  `METRIC_GENEVE_ENCAP_FAIL` on the source with ingress `GENEVE_DECODE_FAIL`
  (ADR-0002) on the peer; persistent pairing indicates a systemic
  headroom/MTU problem, not a policy issue.
- **Root cause is usually MTU/headroom.** The expected steady state has **zero**
  encap failures because headroom for the option is reserved up front (ADR-0002
  D-A; the precise MTU/headroom accounting is its own open concern). A nonzero
  rate is an operational defect to fix at the fabric, not a posture to paper over
  with `FALLOPEN_UNKNOWN`.
- **Live-flippable, no teardown.** Posture is the `runtime_config_map[0]` bit;
  changing it requires no reattach and drops no established connections beyond
  the affected unattributable class.

## Testing Requirements

1. **Default fail-closed (mandatory).** Induce a push failure (undersized
   headroom / MTU-exceeding packet) with `runtime_config_map` unset: assert
   `TC_ACT_SHOT`, a `denied_flows_map` entry with the correct inner `flow_key`
   and `DROP_REASON_GENEVE_ENCAP_FAIL`, one DENY `flow_event`, and
   `METRIC_GENEVE_ENCAP_FAIL` incremented (T2).
2. **Opt-in pass-through.** With bit 0 set, the same induced failure returns
   `TC_ACT_OK`, the frame egresses **without** the identity option, and
   `METRIC_GENEVE_ENCAP_FAIL` is **still** incremented (visibility invariant).
3. **Non-tunnel traffic untouched** under both postures (no false encap-fail
   accounting on local/veth paths).
4. **Two-node end-to-end (MER-28/MER-29).** Egress encap-fail under the default →
   the packet never reaches node B (assert non-delivery + source-side reason).
   With egress fail-open + receiver default → node B denies the flow under the
   unknown-identity posture (asserts the D-D defense-in-depth composition).
5. **Visibility invariant.** `METRIC_GENEVE_ENCAP_FAIL` increments on every
   failure regardless of posture; assert the counter delta equals the induced
   failure count in both modes.
6. **Datapath hygiene.** `tc_egress` stays verifier-clean on 5.15 with no
   unbounded retry/recirculation loop; the failure path contains no packet
   buffering.

## Consequences

- **MER-20** implements the stamp with this posture: reserve/verify headroom,
  attempt the TLV push, and on failure branch on `FALLOPEN_UNKNOWN`
  (`TC_ACT_SHOT` + `denied_flows_map` + DENY event by default; `TC_ACT_OK`
  without the option when opened), always bumping `METRIC_GENEVE_ENCAP_FAIL`.
  Its T2 suite covers both postures and the non-tunnel passthrough.
- **`meridian_types.h`** gains `DROP_REASON_GENEVE_ENCAP_FAIL` (reserved-range
  `drop_reason`, no schema bump) and assigns `METRIC_GENEVE_ENCAP_FAIL` from the
  reserved `metric_id` slots (no map resize, pins preserved). The new metric is
  exported through the MER-30 Prometheus surface.
- **ADR-0001** is unchanged but now shares its flag with this posture; the two
  ADRs together define the complete identity-not-established behavior across both
  directions and both nodes.
- **Out of scope** (its own concern, per ADR-0002): the MTU/headroom accounting
  that makes runtime encap failure rare in the first place. This ADR fixes the
  *behavior on failure*, not the *budget that prevents it*.
