# PRD: Meridian — eBPF-Native Service Mesh Data Plane

**Status:** Draft  
**Author:** [You]  
**Version:** 1.0  
**Last Updated:** June 2026

---

## 1. Executive Summary

Meridian is a production-grade service mesh data plane built on eBPF — the same foundational technology used by Cilium (Google GKE's default CNI), Meta's Katran load balancer, and Cloudflare's network edge. It replaces iptables-based sidecar proxies with kernel-resident eBPF programs that transparently intercept container traffic, enforce mutual TLS identity between services, apply L7 traffic policy, and export per-request telemetry — all at kernel speed with near-zero overhead.

A control plane (xDS-compatible, gRPC streaming API) issues configuration to data plane agents running on each node. The result is a complete service mesh that can be deployed as a standalone system or used as a Kubernetes CNI plugin.

**Why this project exists:** eBPF is genuinely the hardest and most in-demand skill in infrastructure engineering right now. The number of engineers who can write a correct TC (Traffic Control) eBPF program, handle the BPF verifier's constraints, implement socket-level redirects with SOCKMAP, and build a user-space control loop around it is genuinely small. This project puts you in that category. It also demonstrates the full stack: kernel networking, TLS/PKI, distributed systems (control plane), and observability — the exact combination that gets you into Tier-1 infra roles.

---

## 2. Problem Statement

### 2.1 The Sidecar Tax

The traditional service mesh model (Istio + Envoy, Linkerd) deploys a sidecar proxy container alongside every application pod. This has real costs:

- **Memory overhead:** Each Envoy sidecar uses 50-150MB of RAM at idle. In a cluster with 500 pods, that's 25-75GB of RAM reserved purely for proxy processes.
- **Latency:** Every request traverses the TCP stack twice (app → sidecar → network, and network → sidecar → app). Under the sidecar model, all traffic exits the container's network namespace, goes through iptables redirect rules, enters the proxy process, and re-enters the network. This adds 0.2-1ms per hop at typical cluster scales.
- **Operational complexity:** 500 pods = 500 sidecars to version, restart, and debug independently.
- **iptables scale:** iptables rules are evaluated linearly; a cluster with thousands of services creates thousands of rules, and each packet traverses all of them.

### 2.2 The eBPF Revolution

eBPF solves this by moving the data plane into the kernel:

- **TC (Traffic Control) hooks:** eBPF programs attached at the TC ingress/egress hooks on each container's veth interface run for every packet, before the packet enters the full network stack. This is the attachment point for policy enforcement and telemetry.
- **Socket-level redirect:** `BPF_MAP_TYPE_SOCKMAP` with `bpf_msg_redirect_map()` allows two sockets on the same host to bypass the full TCP stack entirely — data goes directly from one socket's send buffer to another's receive buffer at memory bandwidth speeds, never hitting the kernel network stack.
- **No sidecar required:** Policy is enforced in the kernel, not in a userspace proxy. The application communicates directly; the kernel intercepts, validates, and routes.

Cilium adopted this model in 2019-2020. Istio Ambient Mesh (2024 GA) is moving away from per-pod sidecars toward a per-node "ztunnel" proxy. Meridian implements this same architectural shift from scratch, with full eBPF data plane.

### 2.3 The mTLS Problem

Zero-trust networking requires that every service-to-service connection be mutually authenticated (both sides present certificates) and encrypted (TLS). With sidecars, the proxy terminates TLS. With eBPF, you need a different model: a per-node userspace process (the "node proxy") handles TLS termination for all pods on that node, while the eBPF programs redirect traffic to it transparently.

This is exactly how Istio's Ambient Mesh ztunnel works, and how Cilium implements Wireguard-based encryption. Meridian implements mTLS via SPIFFE/X.509 SVIDs with automatic certificate rotation.

---

## 3. Goals and Non-Goals

### 3.1 Goals

- eBPF TC programs that attach to container veth interfaces and enforce L4 policy (allow/deny by source/destination identity) entirely in the kernel
- Socket-level redirect (SOCKMAP) for zero-copy intra-host communication between pods on the same node
- A per-node agent (`meridian-agent`) that manages eBPF program lifecycle, certificate rotation, and identity resolution
- A control plane (`meridian-control`) that issues xDS-compatible configuration (LDS, RDS, CDS, EDS) to agents over gRPC streaming
- SPIFFE/X.509 SVID identity system: every workload gets a certificate identifying it as `spiffe://cluster.local/ns/<namespace>/sa/<serviceaccount>`
- mTLS between all services: inbound connections are authenticated against SPIFFE identity; policy is enforced before the connection reaches the application
- L7 HTTP policy (path/method/header-based routing and access control) via a minimal userspace proxy invoked only for policy-relevant connections
- Per-request telemetry via BPF ring buffers exported to userspace: latency, error rate, byte counts per (source, destination) pair
- Prometheus metrics endpoint on the agent
- OpenTelemetry trace export (span creation for every proxied request)
- `meridian` CLI for policy management, certificate inspection, traffic debugging, and live flow observation
- Works standalone (Linux, no Kubernetes required) and as a Kubernetes CNI plugin (v1)

### 3.2 Non-Goals

- Full Kubernetes CNI (IPAM, pod-to-pod routing) — Meridian is a policy/observability layer, not a CNI replacement (though it can integrate with Cilium)
- Multi-cluster federation (scope for v2)
- WASM plugin extensions (Envoy-style extensibility) — out of scope for v1
- Windows support
- UDP traffic encryption (focus on TCP/HTTP)
- Full Envoy xDS API compatibility — Meridian implements a subset covering the most common use cases

---

## 4. Architecture

### 4.1 Component Overview

```
┌───────────────────────────────────────────────────────────────────┐
│                      Control Plane                                │
│                   meridian-control                                │
│                                                                   │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────────────┐ │
│  │ xDS Server   │  │  CA / PKI   │  │  Policy Store            │ │
│  │ (gRPC stream)│  │ (SPIFFE CA) │  │  (service graph + rules) │ │
│  └──────────────┘  └─────────────┘  └──────────────────────────┘ │
└───────────────────────────────┬───────────────────────────────────┘
                                │ gRPC (xDS: LDS/RDS/CDS/EDS)
                                │ + cert issuance (SVID rotation)
          ┌─────────────────────┼──────────────────────────┐
          │                     │                          │
    ┌─────▼───────┐       ┌─────▼───────┐           ┌─────▼───────┐
    │  Node A     │       │  Node B     │           │  Node C     │
    │  meridian   │       │  meridian   │           │  meridian   │
    │  -agent     │       │  -agent     │           │  -agent     │
    │             │       │             │           │             │
    │ eBPF progs  │       │ eBPF progs  │           │ eBPF progs  │
    │ TC hooks    │       │ TC hooks    │           │ TC hooks    │
    │ SOCKMAP     │       │ SOCKMAP     │           │ SOCKMAP     │
    │ mTLS proxy  │       │ mTLS proxy  │           │ mTLS proxy  │
    └─────────────┘       └─────────────┘           └─────────────┘
          │                     │
    ┌─────▼──────┐        ┌─────▼──────┐
    │  Pod A-1   │        │  Pod B-1   │
    │  (service  │        │  (service  │
    │   frontend)│        │   backend) │
    └────────────┘        └────────────┘
```

### 4.2 Data Plane: eBPF Programs

Meridian attaches four eBPF programs per container veth interface, loaded and managed by the agent:

**`tc_ingress`** — attached to the TC ingress hook of each container's veth (the host side). Runs for every packet entering the host from the container:

1. Parse L3/L4 headers (IP src/dst, TCP port)
2. Look up source workload identity in a BPF hash map (`identity_map`) keyed by pod IP
3. Look up destination workload identity in `identity_map` keyed by dst IP
4. Evaluate the L4 policy map (`policy_map`): is (src_identity, dst_identity, dst_port, proto) allowed?
5. If denied: drop the packet with `TC_ACT_SHOT`, increment a counter in `denied_flows_map`
6. If L7 inspection required (flag set in policy): redirect packet to the node proxy via `bpf_redirect()` to a special netns interface
7. If allowed passthrough: `TC_ACT_OK`

**`tc_egress`** — symmetric, for packets leaving the container. Handles egress policy, marks packets with Meridian tunnel headers for cross-node identity propagation.

**`sk_msg`** (socket message eBPF) — attached to a SOCKMAP for intra-node socket-level redirect:

1. When a pod on this node connects to another pod on this same node, intercept the `sendmsg` call
2. Look up the destination socket in the SOCKMAP
3. Call `bpf_msg_redirect_map()` to deliver the data directly to the destination socket's receive buffer
4. Bypasses the TCP/IP stack entirely — no IP headers are processed, no NIC is involved

**`sock_ops`** (socket operations eBPF) — tracks socket state transitions (connect, established, close) to maintain the SOCKMAP's mapping of `(dst_ip, dst_port) → socket_fd`.

### 4.3 eBPF Maps (Shared State Between Kernel and Userspace)

```
identity_map:       HASH    key=pod_ipv4(4B)   value=identity_t(8B)
                    → Maps pod IPs to their SPIFFE identity numeric ID

policy_map:         HASH    key=policy_key_t{src_id, dst_id, dst_port, proto}
                            value=policy_verdict_t{action, l7_required}
                    → Compiled policy rules evaluated by tc_ingress

sockmap:            SOCKHASH key=(dst_ip, dst_port)  value=socket_fd
                    → For intra-node socket-level redirect

metrics_map:        PERCPU_ARRAY  key=metric_id  value=u64 counter
                    → Per-CPU counters for allowed/denied flows, bytes

ring_buffer:        RINGBUF       size=4MB (configurable)
                    → Per-request flow events streamed to userspace agent

denied_flows_map:   LRU_HASH      key=flow_key_t  value=drop_reason_t
                    → Last N denied flows for debugging (bounded size)
```

### 4.4 Identity System (SPIFFE)

Every workload in Meridian gets a **SPIFFE Verifiable Identity Document (SVID)** — an X.509 certificate with:
- Subject Alternative Name (SAN) URI: `spiffe://cluster.local/ns/<ns>/sa/<sa>`
- Issued by the Meridian CA
- Short-lived (24h), rotated automatically by the agent

**Identity assignment:**
- On Linux without Kubernetes: workload identity is assigned by cgroup path or process label configured by the operator
- On Kubernetes: pod identity = `spiffe://cluster.local/ns/<pod.namespace>/sa/<pod.serviceAccount>`

**Identity propagation in the data plane:**
The `identity_map` eBPF map is the source of truth for IP → identity. The agent writes to this map whenever a pod starts or stops. eBPF programs look up identity entirely in the kernel without any userspace round-trip.

For cross-node traffic, the egress `tc_egress` program encodes the source identity into a Geneve tunnel option header (similar to how Cilium encodes identity in VXLAN headers). The receiving node's `tc_ingress` decodes this and uses it for policy enforcement.

### 4.5 mTLS via Node Proxy

For connections requiring L7 inspection or mTLS, the eBPF program redirects the TCP connection to the **node proxy** — a userspace Go process running on each node:

**Inbound mTLS flow:**
1. External client connects to pod `backend:8080`
2. `tc_ingress` detects L7 inspection required (from policy), redirects to node proxy port 15008
3. Node proxy accepts connection, performs TLS handshake presenting `backend`'s SVID
4. Node proxy verifies client's SVID (mTLS — mutual authentication)
5. Node proxy checks identity-based authz: is this client identity allowed to call `backend`?
6. Node proxy proxies the (now-decrypted) HTTP request to the actual backend application on localhost
7. Records telemetry: trace ID, latency, HTTP status, source/destination identity

**Outbound mTLS flow:**
1. Pod `frontend` connects to `backend:8080`
2. `tc_egress` intercepts, redirects to node proxy port 15001
3. Node proxy CONNECT-tunnels to the destination node's proxy port 15008
4. mTLS established between the two node proxies, certificates exchanged = mutual authentication
5. Source pod identity propagated inside the TLS connection (SPIFFE identity in cert)
6. Application data flows through encrypted tunnel

**Key insight:** The application code sees no difference — it connects to `backend:8080` and gets data back. All mTLS, policy enforcement, and telemetry happen transparently in the kernel (eBPF) and in the node proxy.

### 4.6 xDS Control Plane API

The control plane communicates with agents using a subset of the Envoy xDS v3 API over gRPC:

**CDS (Cluster Discovery Service):** Defines the set of services (clusters) and their load balancing configuration
```protobuf
// Cluster: represents a destination service
Cluster {
  name: "backend.default.svc.cluster.local"
  connect_timeout: 5s
  load_assignment: ClusterLoadAssignment {
    endpoints: [
      LbEndpoint { address: "10.0.1.5:8080", health_status: HEALTHY }
      LbEndpoint { address: "10.0.1.6:8080", health_status: HEALTHY }
    ]
  }
  transport_socket: UpstreamTlsContext {
    // mTLS config for connections to this cluster
  }
}
```

**EDS (Endpoint Discovery Service):** Dynamic endpoint list per cluster (pod IPs as they start/stop)

**LDS (Listener Discovery Service):** Defines how inbound traffic is received

**RDS (Route Discovery Service):** HTTP routing rules — path prefixes, header matches, weighted routing

**Agents consume these via a bidirectional gRPC stream:**
```
Agent → Control Plane: DiscoveryRequest { type_url: "CDS", version_info: "3", node: { id: "node-a" } }
Control Plane → Agent: DiscoveryResponse { type_url: "CDS", resources: [...], version_info: "4" }
Agent → Control Plane: DiscoveryRequest { type_url: "CDS", version_info: "4", ... } // ACK
```

The agent translates received xDS resources into eBPF map updates. A new endpoint in EDS → write new entry to `identity_map`. A policy change → recompile the affected entries in `policy_map`. This is the push-based config propagation model that makes service mesh policy changes take effect in milliseconds.

### 4.7 SPIFFE CA and Certificate Rotation

The control plane runs an internal CA (Certificate Authority) that issues SVIDs:

```
CA hierarchy:
  Root CA (offline, self-signed, 10-year validity)
    └── Intermediate CA (online, 1-year validity, held by meridian-control)
          └── SVID (workload certificate, 24h validity, issued to agent per-workload)
```

**Certificate issuance flow (SPIFFE Workload API / CSR model):**
1. Agent generates an ECDSA P-256 key pair for each workload
2. Agent creates a CSR (Certificate Signing Request) with the SPIFFE URI SAN
3. Agent sends the CSR to the control plane over a mTLS-authenticated gRPC connection (the agent's own node identity is its bootstrap certificate)
4. Control plane validates the CSR: is this agent allowed to request an SVID for this workload identity?
5. Control plane signs the CSR with the intermediate CA key, returns the certificate chain
6. Agent stores the certificate in memory and rotates it at 2/3 of its lifetime (16h for a 24h cert)
7. Agent delivers the certificate to the node proxy via a Unix socket using the SPIFFE Workload API protocol

### 4.8 L7 Traffic Policy

For HTTP traffic, Meridian supports header/path/method-based policies enforced by the node proxy:

```yaml
# Policy definition in meridian control plane
apiVersion: meridian.io/v1
kind: TrafficPolicy
metadata:
  name: backend-api-policy
spec:
  target:
    service: backend
    namespace: default
  inboundRules:
    - source:
        identity: "spiffe://cluster.local/ns/default/sa/frontend"
      http:
        - match:
            path: prefix=/api/
            method: [GET, POST]
          allow: true
        - match:
            path: prefix=/admin/
          allow: false
    - source:
        identity: "spiffe://cluster.local/ns/default/sa/monitoring"
      http:
        - match:
            path: exact=/metrics
            method: [GET]
          allow: true
  circuitBreaker:
    maxConnections: 100
    maxPendingRequests: 50
    consecutiveErrors: 5
    interval: 30s
```

L4 rules (allow/deny by identity + port) are compiled into the `policy_map` eBPF map and enforced entirely in the kernel.

L7 rules (path/method/header) are enforced in the node proxy — the eBPF program redirects connections matching an L7 policy flag to the proxy, which parses the HTTP request and evaluates the rules.

### 4.9 Observability: Ring Buffer Telemetry

Every L4 flow decision and every L7 request proxied through the node proxy generates a telemetry event written to the BPF ring buffer:

```c
// Flow event written by tc_ingress eBPF program
struct flow_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;            // TCP=6, UDP=17
    __u8  verdict;          // ALLOW=0, DENY=1, REDIRECT=2
    __u32 src_identity;     // numeric SPIFFE identity ID
    __u32 dst_identity;
    __u32 bytes;            // packet size
    __u64 latency_ns;       // for SOCKMAP: time from send to receive
};
```

The agent's ring buffer consumer goroutine reads these events at microsecond granularity, aggregates them into:
- Per-(src_identity, dst_identity, dst_port) byte and packet counters → exposed as Prometheus gauges
- Per-request latency histograms
- Denied flow log (identity + reason)
- OpenTelemetry spans for L7 requests (exported to any OTLP receiver: Jaeger, Tempo, Datadog)

### 4.10 Socket-Level Redirect (SOCKMAP) — Deep Dive

This is the technically most impressive feature and deserves detailed specification.

**The problem:** Two pods on the same node communicating via TCP still go through the kernel's full TCP/IP stack: `sendmsg` → TCP send buffer → IP routing → veth → bridge → veth → TCP receive buffer → `recvmsg`. Even though both pods are on the same physical host, every byte traverses the full stack.

**The solution:** `BPF_MAP_TYPE_SOCKHASH` maps `(dst_ip, dst_port)` to a socket file descriptor. When pod A sends to pod B (same node), the `sk_msg` eBPF program intercepts the `sendmsg`, looks up pod B's socket in the SOCKHASH, and calls `bpf_msg_redirect_map()`. The kernel copies data directly from A's send buffer to B's receive buffer — no IP headers, no routing, no NIC involvement.

**Performance implications:** Benchmark results from Cilium's implementation show ~40% latency reduction and ~10% throughput improvement for intra-node pod-to-pod communication. For a service like a backend that makes dozens of database calls per request (all on the same node), this compounds significantly.

**Implementation considerations:**
- `sock_ops` eBPF program: intercepts `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` (new outbound connection) and `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` (new inbound connection). For each, writes `(dst_ip, dst_port) → socket` to the SOCKHASH.
- `sk_msg` eBPF program: attached to the SOCKHASH via `bpf_prog_attach()` with `BPF_SK_MSG_VERDICT`. Called on every `sendmsg`. Performs the redirect or falls through to normal kernel path.
- Interaction with mTLS: SOCKMAP redirect bypasses the node proxy. For connections requiring mTLS, the TC programs must intercept BEFORE SOCKMAP can apply — the ordering of BPF hooks guarantees TC runs first.

---

## 5. Implementation Phases

### Phase 0 — eBPF Toolchain and Foundations (Week 1)

**This phase is entirely about getting the eBPF development environment right.** It is the hardest setup problem in the project.

- Install `libbpf` and `bpftool`; understand CO-RE (Compile Once, Run Everywhere) — eBPF programs compiled with BTF (BPF Type Format) type info can run on different kernel versions without recompilation
- Set up `cilium/ebpf` Go library (the idiomatic way to load eBPF programs from Go)
- Write a skeleton eBPF program (`xdp_pass`) and load it successfully — validate the entire toolchain: Clang compiles `.c` → `.o`, `go generate` with `bpf2go` generates Go bindings, program loads and attaches without verifier rejection
- Implement a basic TC ingress program that counts packets and reports via `PERCPU_ARRAY` map — validate the ring buffer consumer in Go reads the count correctly
- Understand the BPF verifier: bounds checking, pointer arithmetic restrictions, loop unrolling requirements, stack frame limits (512B)
- Set up a test environment: two network namespaces connected by a veth pair, agent running on host, two "pods" (processes in separate netns) communicating

**Key technical risk:** The BPF verifier rejects programs for subtle reasons. A loop that the verifier cannot prove terminates in bounded time is rejected. Packet parsing code must be written to satisfy the verifier's range checks. This takes time to learn.

**Deliverables:**
- Working eBPF toolchain with `bpf2go` code generation
- Packet counter TC program with Go consumer
- Ring buffer write/read validated
- `Makefile` targets for eBPF compilation: `make ebpf` → generates Go bindings

### Phase 1 — TC Policy Engine (Weeks 2-3)

- Implement `tc_ingress` program with full packet parsing (Ethernet → IP → TCP/UDP)
- Implement `identity_map` (pod IP → identity) populated by the agent
- Implement `policy_map` (src_id, dst_id, dst_port, proto → verdict)
- Implement `denied_flows_map` for debugging
- Agent: watch for network namespace creation (via netlink), automatically attach TC programs to new veth interfaces
- Agent: expose gRPC API for the control plane to push identity and policy map updates
- Agent: expose Prometheus metrics for allowed/denied flows, bytes, packets
- Integration test: two processes in separate netns, agent running on host, verify that policy changes take effect immediately — allowed connection succeeds, denied connection is dropped

**eBPF program skeleton:**
```c
// tc_ingress.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);          // pod IPv4
    __type(value, __u32);        // identity ID
} identity_map SEC(".maps");

struct policy_key {
    __u32 src_identity;
    __u32 dst_identity;
    __u16 dst_port;
    __u8  proto;
    __u8  pad;
};

struct policy_verdict {
    __u8 action;       // 0=allow, 1=deny, 2=redirect_l7
    __u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct policy_key);
    __type(value, struct policy_verdict);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  // 4MB ring buffer
} flow_events SEC(".maps");

SEC("tc/ingress")
int tc_ingress_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Bounds-check all packet access (verifier requirement)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Look up identities
    __u32 *src_id = bpf_map_lookup_elem(&identity_map, &src_ip);
    __u32 *dst_id = bpf_map_lookup_elem(&identity_map, &dst_ip);
    if (!src_id || !dst_id) return TC_ACT_OK;  // unknown identity → passthrough

    __u16 dst_port = 0;
    __u8 proto = ip->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        dst_port = bpf_ntohs(tcp->dest);
    }

    struct policy_key key = {
        .src_identity = *src_id,
        .dst_identity = *dst_id,
        .dst_port = dst_port,
        .proto = proto,
    };

    struct policy_verdict *verdict = bpf_map_lookup_elem(&policy_map, &key);
    if (!verdict || verdict->action == 1) {
        // Emit denied flow event to ring buffer
        struct flow_event *ev = bpf_ringbuf_reserve(&flow_events, sizeof(*ev), 0);
        if (ev) {
            ev->src_ip = src_ip;
            ev->dst_ip = dst_ip;
            ev->verdict = 1;  // DENY
            bpf_ringbuf_submit(ev, 0);
        }
        return TC_ACT_SHOT;  // drop
    }

    if (verdict->action == 2) {
        // Redirect to node proxy for L7 inspection
        return bpf_redirect(NODE_PROXY_IFINDEX, 0);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

### Phase 2 — SOCKMAP Intra-Node Redirect (Week 4)

- Implement `sock_ops` program: intercept established connections, write to SOCKHASH
- Implement `sk_msg` program: on sendmsg, look up destination in SOCKHASH, redirect
- Implement the interaction with TC programs: TC ingress runs first, applies policy; SOCKMAP redirect is for policy-allowed same-node connections only
- Benchmark: compare latency and throughput for same-node connections with and without SOCKMAP
- Integration test: verify data integrity (no corruption), verify policy is still enforced (a denied connection should not be SOCKMAP-redirected)

### Phase 3 — Node Agent and Control Plane Protocol (Weeks 5-6)

- `meridian-agent` binary: starts on each node, loads eBPF programs, manages veth attachment lifecycle
- Netlink watcher: subscribe to `RTMGRP_LINK` for interface add/remove events; auto-attach/detach TC programs when pod veth interfaces appear
- gRPC server on agent: receives xDS-format policy and endpoint updates from control plane
- `meridian-control` binary: minimal xDS server (CDS, EDS, LDS, RDS) with in-memory state
- Control plane REST API: `POST /services`, `POST /policies` for human operators
- Agent implements the ADS (Aggregated Discovery Service) stream — one bidirectional gRPC connection to the control plane delivering all resource types
- Policy compiler: translates high-level YAML policies into `policy_map` entries
- Identity registry: maps pod IPs to SPIFFE identity IDs; propagated to agent via xDS
- End-to-end test: three-node cluster simulation (three Linux VMs or three network namespaces), policy changes propagate from control plane to all agents in < 1 second

### Phase 4 — SPIFFE PKI and mTLS (Weeks 7-8)

- Control plane CA: ECDSA P-384 intermediate CA, issues SVIDs on CSR from agents
- Agent SVID management: generate key per workload, create CSR, receive certificate, store in memory, schedule rotation at 2/3 lifetime
- SPIFFE Workload API socket: agent serves a Unix socket per the SPIFFE spec that workloads can use to fetch their current certificate (compatible with standard SPIFFE SDK)
- Node proxy: Go HTTP/1.1 + HTTP/2 proxy that terminates inbound mTLS, authenticates peer SVID, evaluates L7 policy, and proxies to application
- `tc_ingress` updated: connections with L7 policy flag are redirected to node proxy using `bpf_redirect_neigh()` to the proxy's loopback interface on a designated port
- Certificate transparency: every issued SVID is logged to an internal audit log (future: Rekor integration)
- Integration test: service A calls service B with mTLS enforced; verify certificate exchange, identity verification, rejection of unauthorized service C

### Phase 5 — L7 Policy and Observability (Week 9)

- Node proxy: HTTP/2 request parsing, path/method/header-based policy evaluation
- L7 policy rules compiled from control plane YAML into in-memory rule tables (agent fetches via xDS LDS/RDS)
- Circuit breaker: track consecutive failures per upstream; open circuit after threshold; half-open probe
- Ring buffer consumer: agent goroutine reads flow events, aggregates into Prometheus metrics
- OpenTelemetry trace exporter: for L7 requests proxied by node proxy, create spans with source/destination identity labels, HTTP status, latency, export via OTLP gRPC
- `meridian observe flows` — live tail of the ring buffer showing allowed/denied flows in real time
- `meridian observe http` — live HTTP request/response log per service (like `istioctl x describe pod`)

### Phase 6 — CLI and Debugging Tools (Week 10)

```
meridian agent start [--config agent.yaml]       # Start the node agent
meridian control start [--config control.yaml]   # Start the control plane

# Policy management
meridian policy apply -f policy.yaml             # Apply policy from file
meridian policy get <name>                        # Show current policy
meridian policy delete <name>

# Certificate inspection
meridian cert inspect <workload>                 # Show SVID for workload
meridian cert rotate <workload>                  # Force immediate rotation
meridian cert verify <src> <dst>                 # Verify mTLS chain src→dst

# Traffic debugging
meridian flows watch [--src <id>] [--dst <id>]  # Live flow stream
meridian flows denied [--since 5m]               # Recent denied flows with reason
meridian http watch [--service <svc>]            # Live HTTP request log
meridian network graph                           # Show service communication graph

# eBPF map inspection (debugging)
meridian map dump identity                       # Dump identity_map
meridian map dump policy                         # Dump policy_map (compiled rules)
meridian map stats                               # Show map utilization

# Status
meridian status                                  # Agent connectivity + cert validity
meridian services                                # All discovered services + endpoints
```

### Phase 7 — Kubernetes Integration (Weeks 11-12)

- Kubernetes DaemonSet manifest for `meridian-agent`
- Kubernetes Deployment for `meridian-control`
- Watch Kubernetes API for Pod events (pod start/stop → update identity_map via agent)
- Watch Kubernetes API for Service events → update CDS/EDS in control plane
- `MeridianPolicy` CRD (Custom Resource Definition) — apply policies as Kubernetes objects
- Kubernetes admission webhook: intercept pod admission, inject necessary annotations; optionally enforce that all pods have a registered identity before admission
- Helm chart for full deployment
- End-to-end demo: deploy frontend + backend services in Kubernetes, apply L7 policy, observe traffic with `meridian http watch`

### Phase 8 — Hardening and Benchmarking (Week 13)

- BPF program test suite using the kernel's BPF test infrastructure (`bpf_prog_test_run`)
- Policy map correctness: fuzzing with random (src, dst, port) tuples against a reference policy evaluator
- Performance benchmarks:
  - Baseline: two pods communicating without Meridian
  - With TC policy only (allow): measure overhead
  - With SOCKMAP: measure speedup vs baseline
  - Policy rule scale: measure latency at 10, 100, 1000, 10000 policy entries
- Security audit: verify no packet bypasses TC programs; verify SOCKMAP respects policy; test certificate expiry scenarios
- `meridian doctor` — check kernel version, required features (CO-RE, BTF, TC hooks, SOCKMAP, ring buffer), loaded eBPF programs

---

## 6. eBPF Technical Requirements

### 6.1 Minimum Kernel Version

| Feature | Minimum Kernel |
|---|---|
| TC BPF hooks | 4.1 |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 |
| `BPF_MAP_TYPE_SOCKHASH` (SOCKMAP) | 4.18 |
| BTF (CO-RE support) | 5.2 |
| `bpf_redirect_neigh()` | 5.10 |
| BPF ring buffer `bpf_ringbuf_reserve/submit` | 5.8 |
| **Meridian minimum** | **5.10** (Ubuntu 22.04 LTS ships 5.15) |

### 6.2 Required Kernel Config

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_NET_CLS_BPF=y    # TC BPF
CONFIG_NET_ACT_BPF=y
CONFIG_BPF_JIT=y        # Required for performance
CONFIG_DEBUG_INFO_BTF=y # Required for CO-RE
CONFIG_CGROUPS=y
CONFIG_BPF_EVENTS=y     # Ring buffer
CONFIG_SOCK_CGROUP_DATA=y  # SOCKMAP
```

### 6.3 Go eBPF Library Choice

Use **`cilium/ebpf`** (not `iovisor/gobpf`):
- CO-RE support via `bpf2go` code generator
- Idiomatic Go API for map operations
- Well-maintained, used in production by Cilium
- `bpf2go` generates type-safe Go wrappers from `.c` source

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang TcIngress tc_ingress.c -- -I/usr/include/bpf

// Generated: TcIngressObjects, TcIngressMaps, TcIngressPrograms
// Usage:
objs := TcIngressObjects{}
spec, _ := LoadTcIngress()
spec.LoadAndAssign(&objs, nil)

// Attach to TC ingress of interface
filter := &netlink.BpfFilter{
    FilterAttrs: netlink.FilterAttrs{
        LinkIndex: link.Attrs().Index,
        Parent:    netlink.HANDLE_MIN_INGRESS,
        Protocol:  unix.ETH_P_ALL,
    },
    Fd:           objs.TcIngressProg.FD(),
    Name:         "tc_ingress",
    DirectAction: true,
}
netlink.FilterAdd(filter)
```

---

## 7. Data Models

### 7.1 Workload Identity

```go
type WorkloadIdentity struct {
    ID          uint32            // numeric ID stored in eBPF maps
    SPIFFEID    string            // spiffe://cluster.local/ns/<ns>/sa/<sa>
    PodIPs      []net.IP          // IPs mapped to this identity in identity_map
    Certificate *x509.Certificate // current SVID
    PrivateKey  crypto.PrivateKey // current signing key
    ExpiresAt   time.Time
    RotateAt    time.Time         // 2/3 of cert lifetime
}
```

### 7.2 Policy Rule (before compilation to eBPF map)

```go
type PolicyRule struct {
    ID          string
    Source      IdentitySelector  // SPIFFE URI pattern or label selector
    Destination IdentitySelector
    Ports       []PortRule        // empty = all ports
    L7Rules     []L7Rule          // empty = L4 only (enforced in kernel)
    Action      PolicyAction      // Allow, Deny
}

type L7Rule struct {
    HTTP *HTTPRule
}

type HTTPRule struct {
    Paths   []string  // prefix or exact match
    Methods []string  // GET, POST, etc.
    Headers map[string]string  // required headers
}
```

### 7.3 Flow Event (ring buffer)

```go
type FlowEvent struct {
    TimestampNs    uint64
    SrcIP          [4]byte
    DstIP          [4]byte
    SrcPort        uint16
    DstPort        uint16
    Proto          uint8
    Verdict        uint8  // 0=allow, 1=deny, 2=redirect
    SrcIdentity    uint32
    DstIdentity    uint32
    Bytes          uint32
    LatencyNs      uint64  // 0 for non-SOCKMAP flows
    L7StatusCode   uint16  // 0 if not L7
}
```

---

## 8. Configuration

```yaml
# meridian-agent.yaml
node:
  id: "node-1"
  ip: "192.168.1.10"

control_plane:
  addr: "meridian-control:5678"
  bootstrap_cert: /etc/meridian/bootstrap.crt
  bootstrap_key:  /etc/meridian/bootstrap.key

ebpf:
  ring_buffer_size: 4194304  # 4MB
  identity_map_size: 65536
  policy_map_size: 16384
  sockmap_enabled: true

proxy:
  inbound_port: 15008       # mTLS inbound
  outbound_port: 15001      # outbound intercept
  admin_port: 15000         # Envoy-compatible admin API

logging:
  level: info
  format: json

metrics:
  addr: ":9901"             # Prometheus metrics

tracing:
  enabled: true
  otlp_endpoint: "tempo.monitoring:4317"
```

```yaml
# meridian-control.yaml
api:
  grpc_addr: ":5678"
  http_addr: ":8080"

pki:
  root_ca_cert: /etc/meridian/root-ca.crt
  intermediate_ca_cert: /etc/meridian/ca.crt
  intermediate_ca_key:  /etc/meridian/ca.key
  svid_ttl: 24h
  rotation_fraction: 0.667

service_discovery:
  type: kubernetes  # or "static"
  kubernetes:
    kubeconfig: ~/.kube/config

policy:
  default_action: deny  # deny-all by default
  policy_dir: /etc/meridian/policies/

storage:
  type: etcd            # or "memory" for single-node
  etcd:
    endpoints: ["http://etcd:2379"]
```

---

## 9. Non-Functional Requirements

| Requirement | Target |
|---|---|
| TC program overhead | < 5 microseconds per packet for policy evaluation |
| SOCKMAP redirect overhead | < 1 microsecond per message vs no-mesh baseline |
| Policy propagation latency | < 500ms from control plane API call to policy active in kernel |
| Certificate rotation | Zero-downtime; new cert active before old cert expires |
| Memory footprint (agent) | < 50MB RSS (excluding eBPF maps) |
| eBPF map lookup latency | O(1), < 100ns for HASH maps |
| Ring buffer drop rate | < 0.1% at 1M packets/second (ring buffer sized appropriately) |
| Kernel requirement | Linux 5.10+ (Ubuntu 22.04 LTS) |

---

## 10. Testing Strategy

**Unit tests:** Policy compiler (YAML → eBPF map entries), identity registry, xDS resource generation, certificate issuance and rotation logic.

**eBPF program tests:** Use `bpf_prog_test_run` (kernel BPF testing infrastructure) to inject synthetic packets and verify verdicts without a live network. Test every policy action (allow, deny, redirect) and edge cases (unknown identity, malformed packet, IPv6 passthrough).

**Integration tests (network namespace simulation):**
- Create three pairs of network namespaces (simulating three nodes with two pods each)
- Start agent process on host, load TC programs onto all veth interfaces
- Verify allow/deny verdicts with `netcat` connections between namespaces
- Verify policy changes take effect within 500ms
- Verify SOCKMAP redirect works for intra-namespace connections

**mTLS integration tests:**
- Start control plane CA, issue bootstrap certificates to two agents
- Two workloads establish connection via node proxy
- Verify mutual authentication (both sides exchange valid SVID certificates)
- Revoke one certificate; verify connection refused within certificate rotation window
- Verify a workload with an expired certificate cannot establish new connections

**Benchmark suite:**
- `wrk` or `hey` HTTP benchmark: frontend → backend through Meridian vs. without Meridian
- Measure: latency (p50, p95, p99), throughput (RPS), CPU overhead on agent
- SOCKMAP benefit: same benchmark constrained to intra-node; measure latency improvement

**Chaos tests:**
- Kill agent mid-connection: verify existing connections are not dropped (kernel eBPF maps persist without agent)
- Kill control plane: verify agent continues enforcing last-known policy
- Partition: simulate control plane unavailable for 5 minutes; verify certificates near expiry are not silently allowed

---

## 11. Success Criteria

The project is complete when:

1. TC eBPF programs enforce L4 allow/deny policy between any two pods in the test environment, with zero false allows and zero false denies against a reference policy evaluator
2. SOCKMAP redirect is demonstrably faster than baseline TCP for intra-node connections (benchmarked, with numbers in README)
3. A full mTLS connection is established end-to-end: frontend → node proxy (mTLS handshake) → backend node proxy → backend application
4. A policy change issued via `meridian policy apply` is active in all agent eBPF maps within 500ms (measured)
5. `meridian flows watch` shows live denied/allowed flows in real time, with source and destination SPIFFE identity names
6. `meridian http watch` shows per-request HTTP telemetry (method, path, status, latency, source identity)
7. The full benchmarked overhead of Meridian vs no-mesh is documented: expected result is < 5% latency overhead for cross-node mTLS, measurable speedup for intra-node SOCKMAP

---

## 12. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| BPF verifier rejects programs | High | High | Start with the simplest possible programs; add complexity incrementally; always run `bpftool prog load` to test before agent integration |
| Kernel version fragmentation | Medium | Medium | Target 5.10+ (Ubuntu 22.04 LTS); test on exactly that kernel; document requirements clearly |
| SOCKMAP correctness | High | High | Extensive data integrity tests; verify byte-for-byte correctness vs non-SOCKMAP path |
| mTLS proxy latency | Medium | Medium | Profile the proxy hot path; use Go's `sync.Pool` for TLS handshake buffers; keep proxy logic minimal |
| xDS protocol complexity | Medium | Medium | Implement only the subset needed (ADS + CDS + EDS + LDS + RDS); don't try to implement every Envoy extension |
| Agent crash loses in-flight eBPF maps | Low | Medium | eBPF maps are kernel objects; they persist after agent crash if pinned to `/sys/fs/bpf`; agent on restart re-attaches programs to existing maps |
| Certificate rotation failure | Low | Critical | Test rotation exhaustively; set rotation at 2/3 of TTL (not at expiry); have emergency manual rotation CLI |

---

## 13. Appendix: Key Dependencies

```go
// go.mod highlights
require (
    github.com/cilium/ebpf v0.17.0          // eBPF program loading, map operations
    github.com/vishvananda/netlink v1.3.0   // Netlink: TC filter attach, link watch
    google.golang.org/grpc v1.70.0          // xDS control plane gRPC
    github.com/envoyproxy/go-control-plane v0.13.4  // xDS protobuf types
    github.com/spiffe/go-spiffe/v2 v2.3.0  // SPIFFE Workload API client
    github.com/spiffe/spire v1.9.6          // SPIRE agent/server (CA reference)
    go.opentelemetry.io/otel v1.28.0        // OpenTelemetry tracing
    go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.28.0
    github.com/prometheus/client_golang v1.20.0  // Prometheus metrics
    github.com/go-chi/chi/v5 v5.2.5         // HTTP admin API
)
```

---

## 14. Appendix: Reading List (Required Pre-Implementation)

Before starting, deeply read:

1. **Cilium eBPF Reference Guide** — https://docs.cilium.io/en/stable/reference-guides/bpf/ — the most complete explanation of the BPF subsystem available outside the kernel source
2. **Linux kernel TC BPF documentation** — `Documentation/networking/filter.rst` in the kernel tree
3. **`man 2 bpf`** — the full BPF syscall manual
4. **BPF and XDP Reference Guide** — https://prototype-kernel.readthedocs.io/en/latest/bpf/
5. **Cilium SOCKMAP implementation** — read the actual Cilium source in `pkg/sockops/` and `bpf/sockops/`
6. **SPIFFE/SPIRE documentation** — https://spiffe.io/docs/latest/spire-about/
7. **Envoy xDS API proto definitions** — https://github.com/envoyproxy/data-plane-api
8. **Isovalent eBPF labs** — https://isovalent.com/resource-library/labs/ — hands-on eBPF exercises
