# Meridian Development Guide

*A staff-engineer walkthrough for a brand-new CS major.*

This document explains what Meridian does, how it was built, what decisions were made and why, and what you need to learn to contribute. It is written from the perspective of a senior infrastructure engineer looking back at the project — the kind of narrative you'd get in a good onboarding session, not a dry reference manual.

---

## 1. What problem does Meridian solve?

Imagine you have 100 microservices running in containers on a Kubernetes cluster. Two questions become urgent:

1. **Identity & authorization:** How does service A know that the request it just received actually came from service B, and not from an attacker who found an open port? How do you enforce "service B is not allowed to call service A on port 5432" without modifying the applications themselves?

2. **Observability:** How do you see, in real time, which service is talking to which, at what rate, and whether any requests are being denied — again, without modifying any application code?

The classic answer is a *service mesh*: inject a sidecar proxy (usually Envoy) into every pod. The sidecar intercepts all TCP traffic, does mTLS, enforces policy, and emits telemetry.

**The problem with sidecars:** each sidecar is a full user-space proxy. Every packet crosses the kernel twice: once to the sidecar, once to the real application. At high throughput this overhead adds up. Memory usage grows linearly with pod count.

**Meridian's answer:** do the enforcement in the Linux kernel itself using eBPF — a technology that lets you write small, safe programs that run inside the kernel, attached to network events, without modifying the kernel source.

---

## 2. Background concepts you need to understand

Before reading the code, you need to understand the following topics. Each heading is a thing you should study; the descriptions explain *why* Meridian needs it.

### 2.1 Linux networking fundamentals

Linux receives a packet, routes it through several "hook points" (netfilter, TC, XDP) before it reaches the application. Understanding the journey of a TCP SYN from one container to another on the same host is essential.

**What to learn:**
- Network namespaces (`ip netns`) — how containers get isolated networking
- Virtual ethernet pairs (veth) — how pods connect to the host network
- The Linux Traffic Control (TC) subsystem — where Meridian attaches eBPF programs
- TPROXY — a kernel mechanism that lets a proxy "transparently" accept connections destined for another IP/port (Meridian uses this for L7 redirection)

**Resources:** The kernel documentation on `tc-bpf`, the `ip-link` man page for veth, and the `iptables-tproxy` man page.

### 2.2 eBPF

eBPF (extended Berkeley Packet Filter) is the most important technology in this project. Understanding it is non-negotiable.

eBPF lets you write C programs that run *inside* the kernel in a sandboxed environment. A special verifier checks your program before it runs to make sure it cannot crash the kernel or loop forever. The programs are compiled to bytecode and loaded via a system call; they run at specific "hook points" — places in the kernel where interesting events happen.

**Key concepts:**

- **Programs**: Short C programs compiled to eBPF bytecode. Meridian uses `tc_ingress`/`tc_egress` (attached to veth interfaces), `sock_ops` (socket lifecycle events), and `sk_msg` (socket data events).
- **Maps**: Shared data structures between the kernel eBPF program and user-space. Like a hash map or array that both sides can read/write. Meridian uses maps for identity (`identity_map`), policy (`policy_map`), metrics, and the event ring buffer.
- **The verifier**: Statically analyzes every eBPF program before loading. It rejects any program that might crash, loop infinitely, or access memory out of bounds. Writing eBPF C that satisfies the verifier is the hardest part of the project.
- **CO-RE (Compile Once, Run Everywhere)**: A mechanism using BTF (BPF Type Format) to write eBPF programs that work across different kernel versions without recompilation. Meridian generates `vmlinux.h` from BTF and uses it in its C programs.
- **bpf2go**: A Go tool from the cilium/ebpf library. It takes eBPF C source files, compiles them, and generates Go type stubs so you can load and interact with the eBPF programs from Go without writing unsafe pointer arithmetic.
- **SOCKMAP/SOCKHASH**: eBPF maps that hold active socket file descriptors. With `sk_msg`, you can redirect data between sockets inside the kernel, bypassing the full network stack. Meridian uses this for intra-node zero-copy communication (the "fast path").

**Resources:** `docs/subsystems/01-ebpf.md`, the cilium/ebpf Go library docs, and the BPF documentation at kernel.org.

### 2.3 Go systems programming

Meridian is written in Go. Specifically, it makes heavy use of:

- **`syscall` and `golang.org/x/sys`**: Low-level system calls for netlink (network interface events) and BPF.
- **`vishvananda/netlink`**: A Go library wrapping Linux netlink — how the agent watches for new network interfaces (pod vetches).
- **gRPC and Protocol Buffers**: The agent talks to the control plane using gRPC over the xDS (Envoy discovery service) protocol. You don't need to understand Envoy — just that xDS is a standard, versioned, streaming RPC protocol for pushing configuration.
- **`sync` primitives**: The agent is multi-goroutine; maps can be written by the xDS client and read by the TC programs in the kernel simultaneously. Correct synchronization is critical.
- **Build constraints (`//go:build`)**: Meridian uses Linux-only build constraints to keep the eBPF-specific code out of cross-platform builds.

**Resources:** The Go `sync` and `syscall` package docs, the gRPC-Go documentation.

### 2.4 SPIFFE and mTLS

**mTLS** (mutual TLS) means both sides of a connection present a certificate. Instead of just the server proving its identity to the client, both sides authenticate.

**SPIFFE** (Secure Production Identity Framework for Everyone) is a standard for workload identity. Instead of using a username and password, each workload gets an X.509 certificate with a special URI called a SPIFFE ID: `spiffe://trust-domain/path`. Two services can establish mTLS and each knows the SPIFFE ID of the other — that's the identity.

**SVID** (SPIFFE Verifiable Identity Document) is what SPIFFE calls the certificate. Meridian's CA issues SVIDs with a 24-hour TTL and the agent rotates them at 2/3 of their lifetime (16 hours).

**What to learn:**
- X.509 certificates: public key, subject, validity period, extensions (URI SAN is the critical one)
- Certificate chains: Root CA → Intermediate CA → Leaf cert
- How `crypto/x509` and `crypto/ecdsa` work in Go
- The ECDSA algorithm (P-256 for workloads, P-384 for the CA hierarchy)

**Why P-256 for workloads, P-384 for the CA?** P-256 is faster (important for frequent handshakes); P-384 provides stronger long-term security for the CA keys, which are held longer.

### 2.5 Distributed systems concepts

The control plane is a distributed system. Understanding these is essential:

- **xDS / ADS**: Envoy's Aggregated Discovery Service. A single bidirectional gRPC stream over which the server pushes configuration changes; the client ACKs each version after applying it.
- **The ACK/NACK protocol**: If the client receives a bad configuration, it sends a NACK with an error detail. The server then holds the last-known-good configuration. This is Meridian's "fail-closed" mechanism.
- **Last-known-good**: On control-plane disconnect, the agent keeps enforcing whatever policy was last successfully applied. The kernel maps don't change; in-flight connections are unaffected.
- **Schema versioning**: The shared data structures between control plane and kernel are frozen in ADR-0004. Any change requires a version bump; the agent refuses to start against an unknown schema version.

---

## 3. How the project is structured

```
meridian/
├── bpf/                  eBPF C sources and generated Go bindings
│   ├── include/          Shared headers (meridian_types.h, meridian_maps.h)
│   ├── counter.c         Phase-0 packet counter (toolchain test)
│   ├── tc_ingress.c      TC ingress: identity lookup, policy verdict, events
│   ├── tc_egress.c       TC egress: Geneve encap, outbound redirect
│   ├── sock_ops.c        SOCKMAP eligibility gating
│   └── sk_msg.c          SOCKMAP redirect (intra-node fast path)
│
├── cmd/
│   ├── meridian-agent/   The per-node agent binary
│   ├── meridian-control/ The control-plane binary
│   └── meridian/         The operator CLI (Phase 6)
│
├── internal/
│   ├── agent/            Agent internals (supervisor, bpfobj, attach, xds, datapath, …)
│   ├── control/          Control-plane (store, identity registry, REST, ADS server, CA)
│   ├── cc2/              CC-2 wire codec (xDS resource encoding)
│   ├── proxy/            Node proxy stub (L7/mTLS, Phase 4+)
│   └── reference/        Reference policy evaluator (correctness oracle)
│
├── pkg/wire/             Shared cross-boundary types (stdlib only, leaf package)
│
├── test/
│   ├── bpf/              T2 tests (bpf_prog_test_run, verifier-clean load)
│   ├── integration/      T3 tests (live netns, full stack)
│   ├── harness/          Test infrastructure (netns fixture, WaitUntil, reaper)
│   └── vm/               Lima VM configuration
│
└── docs/                 Architecture, ADRs, phase plans
```

---

## 4. Phase-by-phase development story

### Phase 0: Prove the toolchain works

**Goal:** Get a trivial eBPF program to compile, load into the kernel, and communicate with a Go program — without any real functionality.

**What was built:**
- `bpf/counter.c`: A TC program that counts all packets and writes to a PERCPU_ARRAY map.
- `bpf/gen.go`: The `//go:generate` directive that runs bpf2go to produce Go bindings.
- `cmd/meridian-agent/main.go`: Loads the counter, attaches it to an interface, reads the ring buffer, and prints events.

**What was learned:** The eBPF compilation pipeline is fragile. You need a specific clang version, specific flags (`-O2` is mandatory for the verifier), and the committed bindings (`*_bpfel.go` / `*.o`) must be deterministically reproducible. `make verify-gen` was added to CI for this reason.

**Exit gate (MER-7/8/10):** `make ebpf` compiles cleanly; the program loads verifier-clean on a 5.15 kernel; the ring-buffer event arrives in Go.

### Phase 1: Real policy enforcement

**Goal:** Make real allow/deny decisions based on policy loaded from a YAML file.

**What was built:**
- `bpf/tc_ingress.c`: Full TC ingress pipeline (Ethertype gate → IP parse → identity lookup → L4 parse → policy lookup → verdict dispatch → telemetry).
- `bpf/tc_egress.c`: Symmetric egress pipeline with Geneve identity encapsulation for cross-node traffic.
- `internal/reference/evaluator.go`: A pure-Go reference implementation of the policy logic. This is the "oracle" — everything the kernel does must match what this evaluator says. It's deliberately simple; the complexity lives in proving equivalence.
- `internal/control/compiler.go`: Compiles declarative policy (YAML) into flat `wire.PolicyRule` entries the kernel can look up.
- `pkg/wire/`: The shared cross-boundary types: `PolicyRule`, `PolicyRuleKey`, `PolicyVerdict`, `Identity`, etc.

**Map schema frozen (ADR-0004):** At the end of Phase 1, the `policy_map` key/value layout, `identity_map` layout, and all shared struct byte orders are frozen. Nothing downstream can change them without a version bump — a deliberate rigidity that prevents silent cross-boundary drift.

**Exit gate (MER-34):** Five gates: verdict matrix ≡ reference evaluator (P1.1), live policy integration (P1.2), Geneve two-node test (P1.3), compiler ≡ reference property test (CP-2), denied-flows metrics (O-2).

### Phase 2: SOCKMAP and ADS server

**Two parallel workstreams:**

**eBPF lane (the fast path):**
- `bpf/sock_ops.c`: Observes socket lifecycle; inserts eligible sockets into the SOCKHASH map (gated on `SOCKMAP_ELIGIBLE` verdict flag — prevents bypassing mTLS).
- `bpf/sk_msg.c`: When a message arrives, if the destination socket is in the SOCKHASH, redirect directly inside the kernel — no kernel→user→kernel round trip.
- Gate MER-49 (P2.1-N): Proves that DENY, L7-required, mTLS-required, and REDIRECT sockets are *never* inserted. This is a permanent CI gate — SOCKMAP is only a performance optimization; using it to bypass mTLS would be a critical security hole.

**Control-plane lane:**
- `internal/control/store/memory.go`: In-memory policy + identity store with a `Watch()` seam.
- `internal/control/identity/registry.go`: Monotonic uint32 identity allocator (CC-3: never reuses IDs).
- `internal/control/rest/server.go`: REST API for seeding policy from the operator.
- `internal/control/ads/server.go`: ADS server implementing the xDS version/nonce ACK/NACK state machine.

### Phase 3: Agent becomes real

The agent goes from "loads eBPF and reads ring buffer" to a full daemon:

- `internal/agent/linkwatch/`: Watches Linux netlink for new network interfaces (pod vetches appearing when a container starts). Reconciles before subscribing to avoid missed events.
- `internal/agent/xds/client.go`: The real ADS client that connects to `meridian-control`, decodes CC-2 resources, and applies them to the kernel maps.
- `internal/agent/datapath/writer_linux.go`: The *only* place that writes to `identity_map` and `policy_map`. Single-writer pattern enforced by unexported functions and depguard.
- `internal/cc2/codec.go`: The CC-2 wire codec — versioned JSON encoding over xDS.
- `internal/control/ca/ca.go`: PKI-1 — the CA hierarchy. Root (P-384) + Intermediate (P-384), workload SVID signing (P-256, 24h), node cert signing (P-384, 7d).
- `internal/control/ca/bootstrap.go`: PKI-2 — the two-tier node bootstrap credential (CC-4).

**Exit gate (REST→kernel < 500 ms):** A REST `POST /policies` must appear in the kernel `policy_map` in under 500 ms, measured end-to-end on a real Lima VM.

---

## 5. Key design decisions that every contributor must understand

### 5.1 Fail-closed, not fail-open

**Every** safety-critical boundary in Meridian is fail-closed:

- Unknown identity → deny by default (configurable, but deny is the default posture)
- Agent startup with wrong schema version → refuse to start
- ADS NACK → hold last-known-good, never partially apply
- Near-expiry SVID → serve no certificate, not the expired one
- SOCKMAP insertion → only with `ALLOW + SOCKMAP_ELIGIBLE`; any other verdict → no insertion

This is not just a code convention — several CI gates specifically test the *negative* case (things that must NOT happen). If any of these negative tests fails, it's a P0.

### 5.2 Single-sourced cross-boundary contracts

The `policy_map` key layout is defined in C (`bpf/include/meridian_types.h`) and generated as Go types via bpf2go. **Hand-writing a Go mirror is a contract violation.** The PRD had a bug where the C `flow_event` and Go `FlowEvent` drifted — bpf2go eliminates this by construction.

Similarly, the CC-2 xDS encoding (`internal/cc2/`) is the *single* place where control-plane wire format is encoded/decoded. The control plane encodes; the agent decodes. They must agree by sharing this package.

### 5.3 Single-writer pattern for kernel maps

`internal/agent/datapath` is the **only** package that writes to `identity_map` and `policy_map`. This is enforced by:

- Unexported write functions (can't call them from other packages)
- A depguard rule in `.golangci.yml` that prevents any other package from importing `bpf/` (the generated bindings)

This eliminates an entire class of concurrency bugs where two goroutines could race to update the kernel map with inconsistent state.

### 5.4 No sleeps in tests

All tests use `WaitUntil(deadline, condition-poll)` instead of `time.Sleep`. A sleep is a guess; a WaitUntil is a measurement. The propagation SLA (REST→kernel < 500 ms) is measured this way, not by sleeping 500 ms and hoping.

### 5.5 Byte order matters and is the most common integration bug

Kernel maps store values in network byte order (big-endian) when they come from packet headers (IP addresses, port numbers). But identity IDs, allocated by the control plane, are stored in host byte order. Getting this wrong produces silent lookup misses — the program works but never finds the policy. Every field in every cross-boundary struct has an explicit byte-order annotation in the architecture document.

---

## 6. What topics to learn, in order

**Week 1: Linux and Go fundamentals**
1. How TCP/IP works at the packet level (IP header, TCP header, three-way handshake)
2. Linux network namespaces (`ip netns exec` a command, see it get isolated networking)
3. Go fundamentals: goroutines, channels, `sync.Mutex`, `context.Context`
4. `git log --oneline` through this repo's history — read commit messages, they follow conventional commits and explain the *why* of every change

**Week 2: eBPF**
1. Read the BPF Compiler Collection (BCC) tutorial — it has great worked examples
2. Read `bpf/counter.c` in this repo (Phase 0, the simplest possible eBPF program)
3. Understand what `bpf_map_lookup_elem` and `bpf_ringbuf_reserve` do
4. Understand why `#pragma unroll` is needed for loops in eBPF
5. Read `bpf/tc_ingress.c` with `docs/ARCHITECTURE.md §1` open alongside it

**Week 3: The agent**
1. Read `internal/agent/bpfobj/loader_linux.go` — how maps are pinned and reopened
2. Read `internal/agent/datapath/translate.go` and `writer_linux.go` — the translation boundary
3. Read `internal/agent/xds/client.go` — the ADS state machine
4. Run `sudo ./bin/meridian-agent --iface <veth>` and watch it print flow events

**Week 4: PKI and mTLS**
1. Read how X.509 certificates work: subject, SAN, validity, signature
2. Understand ECDSA: public key on an elliptic curve, sign with private key, verify with public key
3. Read `internal/control/ca/ca.go` — the CA implementation
4. Generate a certificate with `openssl` by hand and inspect it with `openssl x509 -text`

**Week 5: Distributed systems**
1. Read the gRPC quickstart for Go
2. Read `internal/control/ads/server.go` and `internal/agent/xds/client.go` together
3. Understand the xDS ACK/NACK protocol: what happens when the agent NACKs?
4. Read `docs/adr/0008-xds-wire-contract.md` — why JSON over gRPC instead of protobuf?

---

## 7. Common mistakes and how to avoid them

**"I'll add a test later."**
Tests are written *first* in this project (TDD). The CI gate for each feature is specified before any implementation code lands. The reference evaluator exists precisely so you can write the test before you write the eBPF C.

**"The test passes, I'm done."**
Each phase has negative-path CI gates that explicitly test things that must *not* happen. After implementing SOCKMAP, you need to prove DENY sockets are never inserted — not just that ALLOW sockets are. Read the gate manifest (`test/gates/manifest.txt`).

**"I'll just hardcode this for now."**
Schema versioning, map pin paths, trust domain, serial numbers — all of these must come from configuration or be generated randomly. Hardcoded values turn into integration bugs when two components disagree.

**"The verifier rejected my program."**
Read the verifier output carefully — it tells you the exact instruction that failed and why. Common causes: pointer arithmetic without a bounds check, stack frame too large (> 512 bytes), loop that the verifier can't prove terminates. The `#pragma unroll` directive tells the compiler to unroll the loop so the verifier can analyze all iterations statically.

**"I'll just sleep for a second to wait."**
Use `WaitUntil`. Sleeps make tests slow and flaky; WaitUntil makes them fast and deterministic.

---

## 8. How this project was managed

Every significant change is tracked as a ticket (MER-N). Tickets have:
- Acceptance criteria defined before implementation begins
- A "gate" test that must pass (an armed entry in `test/gates/manifest.txt`)
- A commit that references the ticket ID

The ticket tracker is `tickets.md` (open) and `docs/PHASE*_TICKETS.md` (per-phase). The gate manifest (`test/gates/manifest.txt`) is the authoritative list of things CI must verify; `armed=yes` means a failure there is a merge blocker.

A "TPM/Auditor" role reviews committed work each cycle and either closes tickets or flags integrity violations (a gate that's marked green but actually failing is a P0 — the MER-44 rule). This role exists because it's easy to green-wash: mark a test as passing when it isn't. The auditor's job is to prevent that.

---

## 9. The remaining work (as of August 2026)

**Phase 3 complete** (gates green, PKI-1/2 landed). Remaining phases:

| Phase | Key deliverables |
|-------|-----------------|
| 4 | TPROXY plumbing (A-5), proxy mTLS in/out, SVID issuance over mTLS gRPC (PKI-3/4), CC-1 echo prototype |
| 5 | L7 policy + circuit breaker, OpenTelemetry traces, live flow + HTTP watch streams |
| 6 | CLI: `meridian policy`, `meridian cert`, `meridian flows`, `meridian map`, `meridian status` |
| 7 | Kubernetes: DaemonSet/Helm, etcd backend, K8s informers, CRD, TokenReview bootstrap |
| 8 | Fuzzing, chaos suite, benchmarks, `meridian doctor` |

The critical path to Phase 4 is the CC-1 echo prototype (ADR-0006): proving that a redirected TCP connection reaches the node proxy with the correct original destination. Everything in Phase 4 depends on this — it's the highest-risk item in the project.
