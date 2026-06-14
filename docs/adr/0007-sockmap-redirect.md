# ADR-0007: SOCKMAP redirect architecture (CC-5)

- **Status:** Accepted (Phase-2 SOCKMAP data-plane contract; MER-64)
- **Date:** 2026-06-13
- **Relates to:** ROADMAP [CC-5](../../ROADMAP.md#cross-cutting-decisions)
  and Top-risk #2 (SOCKMAP policy/mTLS bypass);
  [PHASE2_TICKETS](../PHASE2_TICKETS.md) MER-47, MER-48, MER-49, MER-50,
  MER-57, and MER-58; [PHASE2_GATES](../PHASE2_GATES.md) P2.1-N;
  ARCHITECTURE D13 and planned Phase-2 D18-D20; [ADR-0004](0004-map-schema-freeze.md)
  (`policy_verdict.flags`, `sock_key`, pinned-map conventions).

## Context

Phase 2 adds the intra-node SOCKMAP fast path: `sock_ops` populates a shared
SOCKHASH, and `sk_msg` redirects eligible socket sends through that map. This is
the path that can deliver the Phase-2 latency win, but it is also ROADMAP
Top-risk #2: if a socket enters SOCKHASH when the flow still requires mTLS, L7
policy, redirect-to-proxy, or deny handling, `sk_msg` can silently bypass the
control that should have run elsewhere.

Phase 1 deliberately froze the schema pieces without instantiating the map:
ADR-0004 records `sock_key` and `policy_verdict.flags`, while ARCHITECTURE §2
marks `sockhash` as specified-but-not-instantiated until Phase 2. MER-47/MER-48
turn that specification into kernel objects and kernel behavior. MER-49 is the
permanent negative gate that keeps the bypass invariant tested after the redirect
path grows.

## Decision

### SOCKHASH map shape

Phase 2 instantiates one pinned SOCKHASH named `sockhash`:

| Property | Decision |
|----------|----------|
| Type | `BPF_MAP_TYPE_SOCKHASH` |
| Key | `struct sock_key { __u32 dst_ip; __u16 dst_port; __u16 pad; }` |
| Byte order | `dst_ip` and `dst_port` are network order; `pad` is zero |
| Pinning | `LIBBPF_PIN_BY_NAME`, same pin-root rules as ADR-0004 |
| Max entries | 65536 |
| Writer | `sock_ops` only |
| Reader | `sk_msg` only |

The key remains the ADR-0004/ARCHITECTURE shape: destination IP plus destination
port. Any change to the key fields, byte order, map type, or pinning behavior is
a schema-contract change and must update ADR-0004/ARCHITECTURE rather than being
hidden inside the Phase-2 implementation.

### Gated insertion invariant

`sock_ops` may call `bpf_sock_hash_update()` only after it has resolved the
flow's `policy_key` and found a compiled `policy_verdict` with
`POLICY_FLAG_SOCKMAP_ELIGIBLE` set.

All other verdicts leave SOCKHASH untouched:

- `DENY`
- `REDIRECT`
- `ALLOW` with `POLICY_FLAG_L7_REQUIRED`
- `ALLOW` with `POLICY_FLAG_MTLS_REQUIRED`
- `ALLOW` without `POLICY_FLAG_SOCKMAP_ELIGIBLE`
- policy miss, malformed key material, unsupported protocol, or any ambiguity

This is the CC-5 invariant: SOCKMAP eligibility is a policy property, not an
operator performance toggle. The compiler/reference layer may only produce
`SOCKMAP_ELIGIBLE` for plain L4 `ALLOW` verdicts that require neither L7 policy
nor mTLS; the kernel still re-checks the flag before inserting because the map
write is the bypass point.

MER-49 (P2.1-N) is the permanent enforcement test for this ADR. It must assert
that DENY, L7-required, mTLS-required, REDIRECT, and ALLOW-without-flag flows are
absent from `sockhash`, with an eligible ALLOW+`SOCKMAP_ELIGIBLE` control case
present. That test is not a temporary Phase-2 scaffold; it is the CI guard for
ROADMAP Top-risk #2.

### `sk_msg` redirect contract

`sk_msg` is attached with `BPF_SK_MSG_VERDICT` to the `sockhash` map fd, not to a
cgroup. On `sendmsg`, it looks up the peer socket in `sockhash` by `sock_key`:

- On hit, it calls `bpf_msg_redirect_map()` and returns the redirect verdict.
- On miss, it returns `SK_PASS` so the normal kernel TCP path continues.
- It never inserts into, repairs, or broadens `sockhash`; write authority stays
  in `sock_ops`.

Redirect telemetry follows ARCHITECTURE D13's decision-point emission model. A
successful redirect path emits a `flow_event` decision event with `latency_ns`
populated; misses/fall-through do not become per-packet telemetry. Counters may
record redirect totals, but ring emission remains bounded to decision points.

## Consequences

- The fast path is opt-in per compiled verdict. A missing flag costs performance
  but preserves mTLS, L7 policy, deny, and proxy-redirect semantics.
- The control plane, reference evaluator, agent datapath writer, and kernel agree
  on one flag meaning: `SOCKMAP_ELIGIBLE` means plain L4 allow that may bypass
  proxy/mTLS/L7 handling.
- Restart behavior follows the existing pinned-map posture: the agent re-opens
  `sockhash` and re-attaches programs rather than recreating the map when pins
  are valid.
- Mid-flight policy changes can leave already-inserted sockets present until the
  lifecycle path removes or ages them; this ADR only freezes the insertion and
  redirect contract. MER-51 covers denied-never-redirected behavior at the
  integration gate.
- The permanent negative test is part of the architecture, not just coverage.
  Removing or skipping MER-49 re-opens CC-5.

## Rejected alternatives

### Unconditional insertion

Rejected. Populating SOCKHASH for every established connection and relying on
`sk_msg` to sort it out creates the exact bypass CC-5 is meant to prevent. A
single missing branch in `sk_msg` would silently skip mTLS, L7 policy, or DENY
handling after the socket is already eligible for redirect.

### Runtime perf toggle

Rejected. Treating SOCKMAP as an operator-controlled acceleration knob decouples
the fast path from the policy compiler and makes safety depend on deployment
configuration. Eligibility must be encoded in the compiled verdict so the same
policy fact is visible to the reference evaluator, agent, and kernel.

### `sk_msg` re-evaluates full policy before redirect

Rejected for Phase 2. Duplicating the full verdict resolver in `sk_msg` adds hot
path complexity and a second policy interpretation surface. `sock_ops` owns the
policy-gated insertion point; `sk_msg` only consumes the resulting safe set.

### Fall-through as drop on SOCKHASH miss

Rejected. A miss can mean "not eligible," "not same-node," "not yet inserted,"
or "policy requires proxy/mTLS/L7." Dropping on miss would turn a performance
cache miss into a correctness failure. `SK_PASS` preserves the normal kernel path
and lets the TC/proxy data planes enforce the verdict.
