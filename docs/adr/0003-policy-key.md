# ADR-0003: `policy_key` carries an explicit direction byte

- **Status:** Accepted (Phase 1 contract freeze, MER-14)
- **Date:** 2026-06-12
- **Relates to:** ARCHITECTURE D12 (this decision), D4 (verdict layout), D5
  (snapshot application), CC-2 (compiled-policy wire contract);
  Phase 0 review items P-1/D-5.

## Context

The PRD's `policy_key` is `{src_id u32; dst_id u32; dst_port u16; proto u8; pad u8}`
— the final byte is dead padding that exists only because BPF `HASH` maps
compare full key bytes. Meridian attaches **separate ingress and egress TC
programs** (ARCHITECTURE §1), and the Phase 0 review (P-1) flagged that a
direction-blind key cannot express "A may connect out to B, but B may not
connect in to A" without overloading rule semantics in the compiler. Changing
the key after Phase 1 code consumes it would ripple through `control.Store`,
`Compiler`, `datapath.Writer`, `reference.Evaluator`, and the kernel programs
— so this is decided at the freeze, before any consumer exists.

## Decision

`policy_key` v2 replaces the pad byte with `direction`:

```c
struct policy_key {
    __u32 src_id;     /* host order; 0 = unknown */
    __u32 dst_id;     /* host order */
    __u16 dst_port;   /* HOST order (bpf_ntohs'd before lookup) */
    __u8  proto;
    __u8  direction;  /* enum policy_direction: 0=ingress, 1=egress */
};                    /* 12 bytes — same size as v1 */
```

- The size and all other field offsets are unchanged; only the meaning of
  byte 11 changes (must-be-zero pad → must-be-valid direction).
- `wire.PolicyRuleKey` mirrors it with a typed `Direction uint8` field.
- The agent's v1 rule "zero the pad" becomes "set the direction" — there is
  no optional/wildcard direction; **every compiled rule is direction-explicit**.
  A policy that should apply both ways compiles to two entries. This keeps
  kernel lookups exact-match (one `bpf_map_lookup_elem`, no fallback probe).
- Part of schema v2 (`MERIDIAN_SCHEMA_VERSION = 2`); v1 pins are refused
  (fail closed, D15).

## Rejected alternatives

1. **Separate ingress and egress policy maps.** Two maps with the v1 key.
   Rejected: doubles the pinned-map surface, the agent write paths, and the
   CLI/debug surface; complicates the sock_ops eligibility check (Phase 2),
   which would need to know which map to consult; and the LRU/memory
   accounting splits for no expressiveness gain over one keyed byte.
2. **Keep the direction implicit in the attach point** (ingress program only
   consults rules the compiler labeled ingress, via disjoint identity pairs).
   Rejected: pushes a kernel-enforcement property into compiler convention —
   exactly the silent-divergence class the reference evaluator exists to
   catch; unverifiable from the kernel side.
3. **Widen the key (u16 direction/flags field).** Rejected: changes the key
   size and every offset for one bit of information today; reserved key bits
   in a HASH key are a hazard (any nonzero stray bit is a silent lookup
   miss). If a future need for key flags is real, that is a schema bump
   anyway.
4. **Wildcard direction value (e.g. 255 = both).** Rejected: exact-match
   HASH would require a second lookup on the wildcard value on every packet
   (hot-path cost), and "both" rules become un-auditable in `map dump`
   output. The compiler emitting two explicit entries is equivalent and
   keeps the kernel path single-lookup.

## Consequences

- The policy compiler (MER-23) must emit direction-explicit rules and the
  reference evaluator (MER-22) takes direction as an input.
- `datapath.Writer` (MER-26) sets the byte from `wire.PolicyRuleKey.Direction`;
  the zero value is a valid direction (ingress), so "forgot to set it"
  becomes an ingress rule, not a lookup miss — the wire↔C equivalence test
  (MER-15) and the compiler ≡ reference harness (MER-24) are the nets.
- `tc_egress` (MER-20) looks up with `direction = POLICY_DIR_EGRESS`; the
  open "where is remote-dst egress policy enforced" ADR is unaffected.
