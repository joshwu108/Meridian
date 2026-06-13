# ADR-0006: Original-destination recovery (CC-1) — TPROXY vs eBPF DNAT

- **Status:** Accepted (Phase-4 **entry gate**; formalizes ARCHITECTURE D1).
  The decision is frozen now; Phase 4 may not begin until the no-TLS echo
  prototype (node-proxy P4.1) has demonstrated it end-to-end.
- **Date:** 2026-06-13
- **Relates to:** ROADMAP [CC-1](../../ROADMAP.md#cross-cutting-decisions)
  (the "blocking, highest-leverage" cross-cutting decision) and Top-risk #1 /
  eBPF R3 / proxy R1 (original-destination loss); ARCHITECTURE **D1** (the
  one-line decision this ADR expands) and §"verdict dispatch" item 6 (REDIRECT →
  `skb->mark |= TPROXY_MARK` on SYN), §agent lifecycle `TPROXY_INSTALL` state;
  [01-ebpf](../subsystems/01-ebpf.md) §"redirect-to-proxy handoff",
  [02-agent](../subsystems/02-agent.md) responsibility 7 + A-5 (TPROXY plumbing),
  [05-node-proxy](../subsystems/05-node-proxy.md) §"Original-destination
  interface" + the 15008/15001 listeners; [ADR-0002](0002-geneve-topology.md)
  D-B (Meridian-as-passenger — the DNAT alternative would have Meridian own a new
  hot-path map). Owning ticket **MER-40**. Consumed by A-5 (agent TPROXY rule
  install), node-proxy **P4.1** (echo prototype — the gate), and P4.2–4.4 (proxy
  mTLS in/out).

## Context

Every "redirect to the proxy" sentence in the PRD is shorthand for "redirect
**plus** a way for the proxy to recover what the client was originally trying to
reach." `bpf_redirect()` / `bpf_redirect_neigh()` move an skb to an interface,
but a normal userspace `accept()` on the proxy socket then sees only the
**proxy's** local address — the original `dst_ip:dst_port` the client dialed is
gone. Without a recovery mechanism the proxy cannot pick an upstream, so
interception is non-functional: this is eBPF R3 / proxy R1, ranked the project's
#1 risk, and ROADMAP CC-1.

The interception data path (Phase 4) is: a pod's outbound connection is matched
at the `tc_ingress` hook, flagged REDIRECT by policy, and must arrive at the
local node proxy's outbound listener (`:15001`), which originates mTLS to the
destination node's proxy (`:15008`). For the proxy to act, on **every** accepted
connection it must answer:

> What were the original `(dst_ip, dst_port)` and the resolved
> `(src_identity, dst_identity)` for this connection?

ROADMAP CC-1 names two viable mechanisms and requires picking one **before**
Phase 4, because the choice forces concrete, divergent work on three subsystems
(agent rule/maps, proxy listener type, eBPF schema) that cannot be built against
a "decide later" placeholder. The eBPF REDIRECT verdict (MER-17) currently ships
as a **mark-only placeholder** precisely because this ADR was outstanding; this
freezes what that placeholder becomes.

## Problem Statement

Choose the original-destination recovery mechanism and freeze its cross-subsystem
contract. The decision must fix:

1. **The kernel action** for a REDIRECT verdict — what `tc_ingress` does to a
   proxy-bound connection.
2. **The steering path** from that action to the proxy's listener.
3. **How the proxy recovers** the original 4-tuple.
4. **How the proxy obtains the identities** the kernel already resolved
   (`src_identity`, `dst_identity`) — by re-resolution or by hand-off.
5. **Whether a new pinned eBPF map** is added to the (otherwise frozen) schema.
6. **A swappable seam** so the mechanism can change without rewriting the proxy.

The two candidates:

- **TPROXY + `IP_TRANSPARENT`** (Istio ztunnel-style): TC marks the connection;
  netfilter's `TPROXY` target steers it to a transparent proxy socket; the proxy
  recovers the original destination with `getsockname()`. No DNAT, no per-flow
  map.
- **eBPF DNAT-to-loopback + pinned `orig_dst_map`**: TC rewrites the destination
  to `127.0.0.1:15001/15008` and stores `(client 4-tuple) → (orig_ip, orig_port,
  src_identity, dst_identity)` in a new pinned `LRU_HASH` the proxy reads back.

## Decision

Original-destination recovery is **frozen** on **TPROXY + `IP_TRANSPARENT`**,
with **no orig-dst map in v1**.

### D-A — Kernel: mark on SYN, never `bpf_redirect`

For a REDIRECT verdict, `tc_ingress` does **not** call `bpf_redirect*` and does
**not** rewrite addresses. On the **SYN only** it sets
`skb->mark |= TPROXY_MARK` (a bitwise OR that preserves any other mark bits the
host fabric uses) and returns `TC_ACT_OK`. The connection is otherwise left
byte-intact on the wire. Marking on SYN is sufficient: the mark establishes the
steering decision for the flow, and netfilter's socket/conntrack match carries
subsequent packets to the same transparent socket. An unrecognized or absent
verdict still fails closed (`TC_ACT_SHOT`), unchanged from ADR-0001's posture.

### D-B — Steering: agent-installed `ip rule` + mangle `TPROXY`, netns-scoped

The **agent** owns the steering rules (responsibility 7 / A-5), installed in the
`TPROXY_INSTALL` lifecycle state before it goes READY:

- a policy routing rule `ip rule add fwmark <TPROXY_MARK> lookup <table>` plus a
  local route so marked packets are delivered locally instead of forwarded, and
- an `iptables`/`nft` mangle `TPROXY` target that redirects marked, proxy-bound
  connections to the proxy's transparent listener port (`:15001` outbound,
  `:15008` inbound) without altering the packet's addresses.

These rules are **netns-scoped**, which is also why N simulated nodes can run
colliding `:15008`/`:15001` listeners on one CI host. Per the shutdown contract,
the agent **leaves the rules in place** across restarts (chaos requirement); it
reconciles them to the desired set on boot rather than tearing down on exit.

### D-C — Proxy: `IP_TRANSPARENT` listeners; original dst via `getsockname()`

The node proxy opens its `:15001` and `:15008` listeners with `IP_TRANSPARENT`
(`SOL_IP`/`IP_TRANSPARENT` via `golang.org/x/sys/unix`). On an accepted
transparent connection, `getsockname()` returns the **original**
`dst_ip:dst_port` the client dialed (that is what TPROXY preserves), so the proxy
selects its upstream directly from the recovered tuple.

### D-D — Identities are recovered out-of-band, not carried in the mark

The TPROXY mark carries only the steering bit, not the kernel-resolved
identities. The proxy obtains them without a hand-off map:

- **`src_identity`** on the inbound (`:15008`) path comes from the **peer's mTLS
  client certificate** (SPIFFE SVID) during the handshake — identity is an
  authenticated property of the connection, not an app-layer header, so the proxy
  never trusts a kernel-supplied source identity it cannot cryptographically
  verify.
- **`dst_identity`** is resolved by the proxy from the recovered original
  `dst_ip` via the agent's identity table (the same `identity_map` source of
  truth) — a lookup the proxy can do locally.

This is a deliberate, small re-resolution rather than threading the kernel's
already-computed identities through a new contract. It keeps identity authority
where it belongs (the cert for src, the identity table for dst) and is the second
reason no `orig_dst_map` is needed in v1.

### D-E — Swappable seam: `originalDestination(conn)`

The proxy hides the mechanism behind a single interface,
`originalDestination(conn) (netip.AddrPort, Identities, error)` (subsystem 05).
v1 implements it with `getsockname()` + identity-table lookup; a future DNAT
variant would implement the same interface with an `orig_dst_map` read. No proxy
logic above this seam knows which mechanism is in use, so the rejected
alternative remains reachable without a rewrite if a deployment ever needs it.

## Alternatives Considered

1. **eBPF DNAT-to-loopback + pinned `orig_dst_map`.** Rejected for v1. TC
   rewrites dst to `127.0.0.1:15001/15008` and stashes the original tuple plus
   both identities in a new pinned `LRU_HASH`; the proxy reads it back keyed by
   the client 4-tuple. It does avoid identity re-resolution (D-D) and needs no
   `IP_TRANSPARENT`/TPROXY kernel features. But it (a) adds a **new hot-path map
   to a schema we are freezing** (ADR-0002 / MER-34), with LRU eviction races
   under churn that can mis-attribute a connection — exactly the silent-divergence
   class the reference evaluator exists to guard against; (b) makes Meridian own
   per-flow NAT state and its lifecycle, against the ADR-0002 D-B "passenger, not
   fabric owner" stance; and (c) loopback DNAT mangles the very 4-tuple the proxy
   then has to reconstruct, where TPROXY leaves the packet intact. Kept reachable
   behind D-E, not chosen.

2. **`bpf_redirect()` / `bpf_redirect_neigh()` to the proxy interface, then
   `accept()`.** Rejected — this is the non-mechanism the PRD implies. It
   delivers the packet but discards the original destination for a normal
   `accept()`; the proxy cannot select an upstream. This is the R3 trap CC-1
   exists to close.

3. **Carry the original tuple/identities in an app-layer header** (e.g. a PROXY
   protocol preamble or HTTP header injected by BPF). Rejected: BPF cannot
   cleanly splice an L7 preamble onto an arbitrary TCP stream, it breaks the
   "L4-only flows never touch the proxy" performance premise, and a forgeable
   header as the identity source contradicts cert-based source identity (D-D).

4. **`SO_ORIGINAL_DST` (conntrack/REDIRECT-style) recovery.** Rejected: it is the
   recovery primitive for **NAT REDIRECT**, so it presupposes alternative #1's
   DNAT and inherits its map/NAT-state costs. TPROXY's `getsockname()` recovers
   the original destination *without* NAT, which is the whole point.

5. **Resolve identities in the proxy for the source side too** (drop cert-derived
   src identity in favor of a dst-IP-style lookup). Rejected: the source arrives
   over an mTLS tunnel from a peer node; its trustworthy identity is the
   handshake SVID, not a reverse lookup of a tunnel address. Re-resolution is
   acceptable for `dst_identity` (local, authoritative table) but never for the
   authenticated `src_identity`.

## Security Implications

- **No forgeable identity channel.** Source identity is the verified mTLS client
  cert; nothing in the redirect path lets a workload assert an identity it cannot
  prove. The kernel mark conveys *steering*, not *trust*.
- **Packet integrity to the proxy.** TPROXY preserves the original 4-tuple, so
  the proxy enforces against the destination the client actually dialed — no DNAT
  rewrite to reason about, no map race that could route a connection to the wrong
  upstream or attach the wrong identity.
- **Fail-closed is preserved.** A non-REDIRECT/garbled verdict is still
  `TC_ACT_SHOT` (ADR-0001). A connection that is marked but for which steering or
  the transparent listener is absent does not silently bypass the proxy — it
  fails to establish rather than reaching the upstream unmediated (see D-B
  reconciliation and the doctor probe below).
- **Smaller cross-boundary surface.** No new pinned map exposed across the
  kernel/userspace boundary in v1; one fewer cross-boundary contract to abuse.

## Operational Implications

- **New kernel-feature dependency.** TPROXY requires
  `CONFIG_NETFILTER_XT_TARGET_TPROXY` and `IP_TRANSPARENT` support (Linux ≥ 5.10,
  matching the rest of the data path). `meridian doctor` MUST probe these and the
  agent MUST **fail closed at startup** if they are absent, rather than attach a
  redirect path that cannot steer (mitigates kernel-fragmentation risk R4). CI
  stays pinned to Ubuntu 22.04 / 5.15.
- **Steering rules are agent-owned and restart-surviving.** They live in the
  `TPROXY_INSTALL` state and are left in place on shutdown so in-flight
  connections survive an agent restart; boot reconciles to the desired set.
- **Diagnosability.** The P4.1 echo prototype logs, per accepted connection, the
  `getsockname()` original destination; the e2e assertion is "proxy-logged orig
  dst == intended service." A redirect that reaches the proxy with the *proxy's*
  own address logged means TPROXY/`IP_TRANSPARENT` is misconfigured.
- **Out of scope here** (own concerns): the SOCKMAP/`sk_msg` fast path for
  same-node redirect (a perf optimization that is verdict-gated, not part of
  original-dst recovery); proxy mTLS, CONNECT tunneling, and L7 policy (P4.2+).

## Testing Requirements

1. **P4.1 echo prototype is the gate (mandatory, no-TLS).** TPROXY → proxy →
   echo upstream: a redirected outbound connection reaches the proxy and the
   `getsockname()`-recovered original destination **equals** the intended service
   `dst_ip:dst_port`. Phase 4 does not start until this passes. This de-risks R1
   before any crypto is added.
2. **dst-identity resolution.** The proxy resolves `dst_identity` from the
   recovered original `dst_ip` via the identity table and it matches the kernel's
   `tc_ingress` resolution for the same flow (reference-equivalence in spirit:
   the proxy and kernel agree on dst identity).
3. **Mark semantics.** `tc_ingress` ORs `TPROXY_MARK` on the SYN, preserves
   pre-existing mark bits, and a non-REDIRECT verdict sets no mark (T2 on the
   marked-bytes / returned action).
4. **Fail-closed steering.** With the agent's TPROXY rules absent, a REDIRECT
   connection does **not** reach an upstream unmediated (asserts no silent
   bypass).
5. **Feature-probe fail-closed.** On a kernel lacking
   `CONFIG_NETFILTER_XT_TARGET_TPROXY`/`IP_TRANSPARENT`, the agent refuses to go
   READY (doctor + startup probe), rather than attaching an unsteerable redirect.
6. **netns isolation (T3).** Two simulated nodes run colliding `:15001`/`:15008`
   transparent listeners without cross-talk, proving the netns-scoping claim.
7. **Seam abstraction.** `originalDestination(conn)` is the only place the
   recovery mechanism is named; a unit test substitutes a fake implementation to
   prove no proxy logic above the seam depends on TPROXY specifics (keeps the
   DNAT alternative swappable).

## Consequences

- **MER-17's REDIRECT placeholder is now specified.** When the verdict path is
  promoted from "mark-only placeholder" to live (Phase 4), it implements D-A:
  `skb->mark |= TPROXY_MARK` on SYN, `TC_ACT_OK`, no `bpf_redirect`, no address
  rewrite.
- **Agent (A-5 / responsibility 7)** gains the `TPROXY_INSTALL` work: install and
  reconcile the `ip rule` + mangle `TPROXY` steering, netns-scoped, restart-
  surviving; add the TPROXY/`IP_TRANSPARENT` checks to `meridian doctor` and the
  fail-closed startup probe.
- **Node proxy** opens `IP_TRANSPARENT` listeners on `:15001`/`:15008`,
  implements `originalDestination(conn)` via `getsockname()` + identity-table
  lookup, and takes `src_identity` from the mTLS client cert (D-D).
- **eBPF schema is unchanged.** No `orig_dst_map` is added in v1, so the Phase-1
  map-schema freeze (ADR-0002 / MER-34) is **not** reopened by interception. If a
  future deployment requires the DNAT variant, adding `orig_dst_map` is a
  schema-versioned change implemented behind the D-E seam, not a v1 obligation.
- **ROADMAP / risk register.** CC-1 is marked a **Phase-4 entry gate** in
  ROADMAP, validated by the P4.1 no-TLS echo prototype (closing R3/R1 before any
  TLS work). The build-order week 7–8 exit gate's "CC-1 resolved before this
  phase starts" now points here.
