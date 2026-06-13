# Subsystem 2 — Node Agent (`meridian-agent`)

> The per-node userspace daemon: eBPF program lifecycle, veth auto-attachment, xDS consumption → eBPF map writes, SVID lifecycle, Workload API socket, transparent-proxy plumbing. PRD Phases 1 (stub), 3 (full), 4 (PKI duties).

The agent is the **integration hub** — every other subsystem terminates at it. It owns no policy decisions of its own: it faithfully translates control-plane intent into kernel and proxy state.

## Responsibilities

**Owns:**

1. **eBPF program lifecycle.** Load bpf2go-generated objects; attach `tc_ingress`/`tc_egress` to host-side veths (clsact), `sock_ops` to the cgroup root, `sk_msg` to the SOCKHASH; pin all maps under `/sys/fs/bpf/meridian/`; on restart **re-open pinned maps (never re-create)** and re-attach program FDs so live policy state and in-flight connections survive (PRD §12 chaos requirement).
2. **Veth attachment lifecycle.** Netlink watcher on `RTMGRP_LINK`: auto-attach TC programs when pod veths appear, detach/clean up on removal. On startup, perform a **full interface reconcile** (events missed while the agent was down are otherwise lost).
3. **xDS ADS client.** Single bidirectional stream to `meridian-control`; ACK only after a snapshot is fully applied; NACK with `error_detail` on any translation failure; enforce last-known-good when the control plane is unreachable.
4. **xDS → kernel/proxy translation.** EDS endpoints + identity metadata → `identity_map` writes; compiled L4 verdicts → `policy_map` writes; LDS/RDS L7 rules → immutable snapshot pushed to the node proxy. **Write ordering matters:** identities before the policies that reference them; on policy shrink, remove allows before adding (never transiently widen).
5. **SVID lifecycle (the agent half of the SPIFFE subsystem).** Per-workload ECDSA P-256 keygen → CSR → `FetchSVID` over the node-cert mTLS channel → in-memory store → rotation at 2/3 lifetime with make-before-break swap.
6. **SPIFFE Workload API server.** Unix socket serving `FetchX509SVID` (streaming) + `FetchX509Bundles` to the node proxy and workloads.
7. **Transparent-proxy plumbing.** Install the TPROXY `ip rule`/mangle steering (or pin `orig_dst_map`) per cross-cutting decision CC-1. This was missing from the PRD and is assigned here.
8. **Node-local gRPC/admin surface.** Backs CLI debugging (`meridian map dump`, `meridian status`) and streams flow events to `meridian flows watch` (see [observability](06-observability.md)).

**Not its job:** allocating identity IDs or compiling policy (control plane); signing certificates (CA); TLS data path or L7 parsing (node proxy); producing flow events (eBPF programs); aggregating telemetry semantics beyond what observability defines.

## Interfaces

| Boundary | Direction | Peer | Form |
|---|---|---|---|
| ADS stream | client | control plane | gRPC `StreamAggregatedResources`, node-cert mTLS, ACK/NACK per type_url |
| SVID issuance | client | control plane CA | `FetchSVID`/`FetchBundle` gRPC over the same mTLS channel |
| BPF maps | writer | kernel / eBPF programs | pinned maps at `/sys/fs/bpf/meridian/<name>`; `cilium/ebpf` map ops |
| TC attach | control | kernel | netlink clsact filter add/del (`vishvananda/netlink`) |
| Netlink link watch | subscriber | kernel | `RTMGRP_LINK` subscription + startup reconcile scan |
| Workload API | server | node proxy, workloads | SPIFFE Workload API over Unix socket |
| L7 rule snapshots | producer | node proxy | atomically-swapped immutable `[]CompiledL7Rule` (loopback gRPC or in-process) |
| Ring buffer | consumer | eBPF | `flow_event` decode → observability pipeline |
| Metrics | server | Prometheus scraper | `:9901`, shared registry (proxy registers into it) |
| Admin/debug | server | CLI | map dump, status, flow streaming |

## Dependencies

- **Libraries:** `cilium/ebpf`, `vishvananda/netlink`, `grpc`, `spiffe/go-spiffe/v2`, `prometheus/client_golang`.
- **Artifacts:** bpf2go-generated bindings from the eBPF subsystem (build-time dependency); frozen map schemas; the xDS metadata contract (CC-2); node bootstrap credential (CC-4).
- **Minimal forms by phase:** Phase 1 needs only the **agent stub** (static file → map writes, manual TC attach). Phase 3 adds netlink watcher + ADS client against the control plane. Phase 4 adds the SVID lifecycle + Workload API socket.

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| 1 | **Restart correctness** — re-creating (rather than re-opening) pinned maps wipes policy mid-flight; missed netlink events while down leave veths unattached (unenforced or broken pods) | High / High | Re-open pinned maps via `LoadPinOptions`; full interface reconcile on startup diffed against desired state; chaos test: kill agent mid-connection, verify existing connections survive and policy still enforces |
| 2 | **Map write ordering / transient widening** — policy updates applied non-atomically can briefly allow denied traffic or deny allowed traffic | High / High | Apply snapshots in a safe order (add-then-remove for tightening direction awareness; identities before referencing policies); per-snapshot generation marker; integration test asserting no transient false-allow during a policy swap |
| 3 | **Translation correctness** — the agent is the second half of the compiler-correctness chain (control plane compiles, agent writes); a byte-layout or endianness slip breaks every lookup | Med / Critical | Use only bpf2go-generated key/value types (never hand-rolled structs); zero padding explicitly; round-trip test: write entry → kernel-side `bpf_prog_test_run` lookup verdict matches reference evaluator |
| 4 | **Attach race on pod startup** — packets flow before identity/policy entries exist; PRD makes unknown-identity = passthrough, so a new pod is briefly unenforced | Med / High | Decide posture per CC-5; if strict: attach a default-deny program first, then populate maps, then mark ready (K8s: gate pod readiness on registration via the admission webhook) |
| 5 | **Ring buffer consumer falling behind** → event drops (NFR < 0.1% at 1M pps) | Med / Med | Dedicated consumer goroutine, batched reads, bounded processing; drop counter surfaced as a metric; see observability |
| 6 | **Memory footprint** — NFR < 50 MB RSS excluding maps | Low / Med | Avoid caching full xDS snapshots redundantly; benchmark RSS in CI at 10k identities / 16k policies |

## Implementation order

1. **A-1 (Phase 1) — Agent stub.** Load + attach TC programs to named veths; write `identity_map`/`policy_map` from a static YAML file; pin maps. **Gate:** the eBPF P1.2 netns integration test passes using the stub; restart the stub and verify maps survived (pin re-open path).
2. **A-2 (Phase 3) — Netlink lifecycle.** `RTMGRP_LINK` watcher + startup reconcile; auto attach/detach. **Gate:** create/destroy netns+veth in a loop; every veth gets programs within 100 ms; no leaked attachments.
3. **A-3 (Phase 3) — ADS client + translation.** Stream to `meridian-control`, apply snapshots with safe ordering, ACK/NACK. **Gate:** end-to-end propagation REST → kernel map < 500 ms (success criterion #4, measured for real); NACK on a malformed resource holds last-good.
4. **A-4 (Phase 4) — SVID lifecycle + Workload API socket.** Keygen/CSR/rotation per [SPIFFE PKI-4](04-spiffe.md); serve the socket. **Gate:** fake `go-spiffe` client receives initial SVID and pushed rotation.
5. **A-5 (Phase 4) — TPROXY plumbing.** Install steering rules for the proxy (CC-1). **Gate:** node-proxy P4.1 echo prototype receives redirected connections with correct original destination.
6. **A-6 (Phase 8) — Hardening.** Restart/chaos suite, RSS benchmark, `meridian doctor` probes.

Buildable in isolation: translation layer (against frozen schemas + `bpf_prog_test_run`), ADS client (against the control plane or its conformance suite), SVID lifecycle (against a local test CA).
