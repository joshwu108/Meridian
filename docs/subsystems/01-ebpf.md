# Subsystem 1 — eBPF Data Plane

> Kernel-resident programs (`tc_ingress`, `tc_egress`, `sk_msg`, `sock_ops`), BPF maps, CO-RE/bpf2go toolchain, map pinning, verifier strategy. PRD Phases 0–2.

**Critical finding:** the PRD describes the redirect-to-proxy handoff at a level that does not work as written. `bpf_redirect()` / `bpf_redirect_neigh()` move a packet to an interface, but they do not preserve the original L3/L4 destination in a way a normal userspace `accept()` can recover. Every "redirect to proxy" sentence in the PRD is shorthand for "redirect **plus** an original-destination recovery mechanism" (TPROXY or an eBPF orig-dst map). See [cross-cutting decision CC-1](../../ROADMAP.md#cross-cutting-decisions).

## Responsibilities

**Owns:**

- **L3/L4 packet-path policy enforcement.** `tc_ingress`/`tc_egress` parse Ethernet→IP→TCP/UDP, resolve identities from `identity_map`, evaluate `policy_map`, return `TC_ACT_OK` (allow), `TC_ACT_SHOT` (deny), or a redirect verdict (L7/mTLS required). Budget: < 5 µs/packet (PRD §9).
- **Identity-to-IP resolution as kernel state.** `identity_map` is the authoritative IP→numeric-identity table. This subsystem owns the *schema and lookup semantics*; the agent owns *population*.
- **Cross-node identity propagation.** `tc_egress` encodes source identity into a Geneve tunnel option; the peer's `tc_ingress` decodes it before policy evaluation.
- **Intra-node zero-copy redirect.** `sock_ops` maintains `(dst_ip,dst_port)→sock` in the SOCKHASH; `sk_msg` performs `bpf_msg_redirect_map()` — for policy-allowed, same-node, non-L7, non-mTLS flows **only**.
- **Telemetry emission.** Ring-buffer `flow_event` records, `metrics_map` PERCPU counters, `denied_flows_map` bounded debug log.
- **Map pinning contract.** All maps pinned under `/sys/fs/bpf/meridian/` so state survives agent restart (PRD §12 chaos requirement).

**Not its job:** TLS, certificates, or L7 parsing (node proxy); IPAM/routing/CNI datapath (non-goal §3.2); policy authoring or compilation (control plane + agent); UDP encryption; IPv6 enforcement (explicit passthrough in v1); map population from the network (only the agent writes `identity_map`/`policy_map`).

## Interfaces

### Attach points and hook ordering

| Program | Hook | Attach mechanism |
|---|---|---|
| `tc_ingress` | TC clsact ingress on host-side veth | `netlink.FilterAdd` BPF filter, `DirectAction=true` |
| `tc_egress` | TC clsact egress on host-side veth | same, egress parent |
| `sock_ops` | cgroup v2 root (`BPF_CGROUP_SOCK_OPS`) | `bpf_prog_attach` to cgroup fd |
| `sk_msg` | SOCKHASH (`BPF_SK_MSG_VERDICT`) | `bpf_prog_attach(prog, sockhash_fd, ...)` |

**Critical ordering invariant:** TC runs in the packet path; `sk_msg` runs in the socket-send path. `sock_ops` must be **gated**: it may only insert a socket into the SOCKHASH if the flow's verdict is ALLOW-passthrough (not DENY, not L7-redirect, not mTLS-required). Otherwise `sk_msg` silently bypasses mTLS and L7 policy. Mechanism: `sock_ops` checks the policy verdict (a "sockmap-eligible" bit in `policy_verdict.flags`) before `bpf_sock_hash_update()`.

### BPF map schemas

```c
// identity_map — IP → numeric identity. Agent writes, BPF reads.
BPF_MAP_TYPE_HASH      max_entries=65536
  key:   __u32 pod_ipv4        value: __u32 identity_id
// PRD §4.3 says 8B value, §6.3 skeleton uses __u32 — resolve to __u32 for v1.

// policy_map — exact-match compiled L4 rules. Agent writes, BPF reads.
BPF_MAP_TYPE_HASH      max_entries=16384
  key:   struct policy_key { __u32 src_id; __u32 dst_id; __u16 dst_port; __u8 proto; __u8 pad; }
  value: struct policy_verdict { __u8 action; __u8 flags; }  // 0=allow,1=deny,2=redirect_l7
// pad MUST be zeroed by the agent — HASH compares full key bytes.

// sockmap — intra-node redirect targets. sock_ops writes, sk_msg reads.
BPF_MAP_TYPE_SOCKHASH  max_entries=65536
  key:   struct sock_key { __u32 dst_ip; __u16 dst_port; __u16 pad; }

// metrics_map — PERCPU_ARRAY, fixed metric_id enum → __u64 counters.
// ring_buffer — RINGBUF, 4MB default, struct flow_event records.
// denied_flows_map — LRU_HASH 4096, flow_key → drop_reason.
```

**`flow_event` canonical layout** (must be byte-identical between C and Go — the PRD's C struct §4.9 and Go struct §7.3 disagree; `L7StatusCode` exists only in Go):

```c
struct flow_event {
    __u64 timestamp_ns;     // 0
    __u32 src_ip, dst_ip;   // 8, 12
    __u16 src_port, dst_port; // 16, 18
    __u8  proto, verdict;   // 20, 21
    __u16 _pad0;            // 22
    __u32 src_identity, dst_identity, bytes; // 24, 28, 32
    __u32 _pad1;            // 36
    __u64 latency_ns;       // 40
    __u16 l7_status_code;   // 48
    __u16 _pad2[3];         // 50..55 → 56 bytes, 8-byte aligned
};
```

Define every cross-boundary struct **once in a shared C header** and generate the Go mirror via `bpf2go`; never hand-write the Go side.

### Redirect handoff to the node proxy (load-bearing interface)

Two viable mechanisms — pick one before Phase 4 (CC-1):

1. **TPROXY (recommended; matches Istio ztunnel):** TC sets `skb->mark`; the connection is steered to the proxy's `IP_TRANSPARENT` listener; proxy recovers original destination via `getsockname()`. Requires the agent to install the TPROXY routing rule — not currently a PRD deliverable, must be added.
2. **eBPF DNAT-to-loopback + `orig_dst_map`:** TC rewrites dst to `127.0.0.1:15008/15001` and stores `(client 4-tuple) → (orig_ip, orig_port, src_identity, dst_identity)` in a new pinned LRU_HASH that the proxy reads.

Contract either way: the proxy must be able to answer "what was the original `dst_ip:dst_port` and the resolved identities for this accepted connection?"

### Geneve identity option (cross-node)

`tc_egress` pushes a Geneve option (4-byte body = `src_identity`); peer `tc_ingress` parses it and uses the carried ID as `src_identity` (the remote IP won't be in the local `identity_map`). The identity ID space must therefore be **cluster-global** (CC-3).

## Dependencies

- **Kernel:** Linux ≥ 5.10 (ring buffer 5.8, SOCKHASH 4.18, `bpf_redirect_neigh` 5.10, BTF 5.2). Config per PRD §6.2; TPROXY additionally needs `CONFIG_NETFILTER_XT_TARGET_TPROXY` + `IP_TRANSPARENT`.
- **Toolchain:** clang/LLVM BPF target, libbpf headers, bpftool, `vmlinux.h` from BTF, `cilium/ebpf` `bpf2go`.
- **Go:** `cilium/ebpf` v0.17, `vishvananda/netlink` v1.3.
- **Meridian subsystems:** agent in *stub form* (writes a handful of map entries from a static file) suffices for Phases 0–2. Control plane and SPIFFE are **not required** — numeric identities are opaque integers to the kernel.

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| R1 | **BPF verifier rejection** — esp. the Geneve TLV walk (unbounded-loop proof) and bounds checks on every deref | High / High | Simplest program first, add incrementally; bounded `#pragma unroll` with hard max-options cap; null-check every map deref; `bpftool prog load` + `bpf_prog_test_run` in CI on the exact target kernel; keep verifier logs as artifacts |
| R2 | **SOCKMAP policy bypass / data integrity** — wrong SOCKHASH insertion silently bypasses mTLS/L7; partial-send semantics can corrupt streams | High / High | Gate `sock_ops` insertion on the sockmap-eligible verdict bit; CI negative test (DENY and L7 flows must not appear in SOCKHASH); byte-for-byte integrity test vs plain TCP on multi-MB streams; fall through to stack on any ambiguity |
| R3 | **Original-destination loss** — `bpf_redirect*` alone gives the proxy no original dst; interception is non-functional without TPROXY/orig-dst plumbing | High / Critical | Make CC-1 a Phase-4 *entry gate*; prototype TPROXY → echo listener before any TLS; e2e assertion: proxy-logged orig dst == intended service |
| R4 | **Kernel fragmentation** — TPROXY availability, clsact, `bpf_redirect_neigh` behavior differ across 5.10→6.x | Med / Med | Pin CI to Ubuntu 22.04 / 5.15; `meridian doctor` feature probes; fail closed at startup if a feature is absent |
| R5 | **Geneve encap vs underlay/CNI** — MTU pressure; collision with an existing overlay (Cilium/Calico) | Med / Med | Identity-encap opt-in; document MTU headroom; non-encap fallback; test on flat L2 first |
| R6 | **Ring buffer drop under load** — per-packet events would overrun 4MB at 1M pps | Low / Med | Emit ring events on decision points (deny, redirect, connection-open), not per-packet; PERCPU counters for byte/packet aggregates; count reserve failures, never block |

## Implementation order (PRD Phases 0–2)

1. **P0.1 — Toolchain spine.** clang→`.o`→`bpf2go`→Go load for a no-op TC program. **Gate:** loads and attaches on the 5.15 target with zero verifier errors; `make ebpf` is deterministic. *No network needed.*
2. **P0.2 — Packet counter + ring readback.** **Gate:** Go-side count matches injected packets; ring record decodes at correct offsets. *Via `bpf_prog_test_run`.*
3. **P1.1 — Full parser + verdicts, test-run only.** **Gate:** synthetic packets covering allow / deny / redirect / unknown-identity passthrough / malformed / IPv6 passthrough all match a Go reference evaluator. *Fully isolated.*
4. **P1.2 — Live netns integration.** Two netns + veth, static map seeding. **Gate:** allowed `netcat` succeeds, denied drops; flipping a `policy_map` entry takes effect immediately; `denied_flows_map` shows the drop.
5. **P1.3 — Egress + Geneve identity option.** **Gate:** two-"node" test decodes remote `src_identity` correctly and enforces policy on it.
6. **P2.1 — Gated `sock_ops` SOCKHASH population.** **Gate:** allowed flow's socket present; denied and L7-redirect flows absent (R2 negative test).
7. **P2.2 — `sk_msg` redirect + integrity + benchmark.** **Gate:** byte-for-byte integrity vs plain TCP; measured intra-node latency win; denied flow never redirected.

Buildable in isolation before any live network: P0.1, P0.2, P1.1, and the policy reference-evaluator fuzz harness.
