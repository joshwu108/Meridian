# Subsystem 3 — Control Plane (`meridian-control`)

> xDS-compatible ADS gRPC server (CDS/EDS/LDS/RDS subset), policy store + compiler, identity registry, operator REST API, storage backends, Kubernetes watchers. PRD Phases 3 and 7.

## Responsibilities

**Owns:**

1. **ADS gRPC streaming server.** One Aggregated Discovery Service bidirectional stream per agent, multiplexing CDS/EDS/LDS/RDS over `StreamAggregatedResources`, with ACK/NACK versioning, per-(node, type_url) version bookkeeping, and push on state change.
2. **Policy store.** Authoritative persisted set of `TrafficPolicy` objects plus the derived service graph; CRUD via REST and (Phase 7) the `MeridianPolicy` CRD.
3. **Policy compiler.** Translates high-level `TrafficPolicy` into (a) flat L4 entries shaped exactly like `policy_key_t → policy_verdict_t` for the kernel `policy_map`, and (b) L7 rule tables carried via LDS/RDS for the node proxy. This is the component PRD success criterion #1 targets: **zero false allows / zero false denies vs a reference evaluator.**
4. **Identity registry.** Bidirectional mapping `SPIFFE ID ↔ numeric uint32 ID ↔ {pod IPs}`. Sole owner of numeric ID allocation (CC-3). Publishes IP→ID via EDS; publishes ID assignments referenced by compiled policy.
5. **Operator REST API.** `POST/GET/DELETE /services`, `/policies`, `GET /status` — backs the CLI (`meridian services`, `policy get`, `status`).
6. **Storage backend.** Pluggable `memory` (dev/test oracle) and `etcd` behind one interface.
7. **Kubernetes watchers (Phase 7).** Pods/Services → EDS endpoints + identity registration; `MeridianPolicy` CRD → policy store; optional admission webhook hook-point.

**Not its job:** full Envoy xDS (no SDS-over-xDS, scoped routes, VHDS, delta-xDS, WASM/ECDS); multi-cluster federation; CNI/IPAM; touching eBPF maps (it produces the contract, the agent performs `bpf_map_update_elem`); L7 enforcement (node proxy); telemetry aggregation (agent).

## Interfaces

### (A) ADS bidirectional gRPC stream — consumer: agent

Service: `envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources`.

ACK/NACK semantics (must be exact):

- Fresh `nonce` per response, monotonic `version_info` per `type_url`.
- Request with latest nonce and no `error_detail` = **ACK**; with `error_detail` = **NACK** (do not advance accepted version; keep last-good logically active for that agent).
- Stale nonce: ignored for versioning, may update `resource_names` subscriptions.
- Initial request: empty `version_info` and `response_nonce`.
- **Dependency-ordered push (warming):** CDS before its EDS, LDS before its RDS; never reference a child resource whose parent hasn't been sent.

Meridian-specific payloads (numeric identity IDs, compiled L4 verdicts, `l7_required`) ride in cluster/endpoint **filter metadata**; L7 rules in RDS route match/typed-config. The metadata schema is a frozen contract with the agent (CC-2).

### (B) Operator REST API — consumers: CLI, operators, CI

`POST /services`, `GET /services`, `POST /policies` (202; compilation + push is async, returns `policyVersion`), `GET/DELETE /policies/{name}`, `GET /status` (health, connected agents, last pushed versions per agent). Consistent envelope `{success, data, error, meta}`; all writes schema-validated, fail closed.

### (C) Storage interface — internal

```text
PolicyStore:   List/Get/Put/Delete(Policy);  Watch() <-chan PolicyEvent
ServiceStore:  List/Get/Put/Delete(Service); Watch() <-chan EndpointEvent
IdentityStore: Allocate(spiffeID) (id, err); Lookup(spiffeID|id|ip); Bind(id, ips); Release(spiffeID)
```

`memory` = immutable snapshots (test oracle); `etcd` = clientv3 under `/meridian/...`, Watch via etcd revisions. Watch channels trigger ADS recompute + push.

### (D) Kubernetes watchers (Phase 7) — source: kube-apiserver via client-go informers

Pod informer → `IdentityStore.Bind` + EDS churn; Service informer → CDS/EDS; `MeridianPolicy` CRD → policy store.

### (E) Inbound dependency on SPIFFE

ADS requires mTLS using the agent's node identity; the peer SPIFFE ID from the handshake is the `node.id` authorization principal.

## Dependencies

- **Libraries:** `envoyproxy/go-control-plane` v0.13 (types; evaluate its snapshot cache vs a hand-rolled ADS loop — the cache's versioning may not map onto per-agent identity-scoped views; decide by end of Phase 3, record as ADR), `grpc`, `etcd/client/v3`, `k8s.io/client-go` (Phase 7), `go-chi/chi/v5`.
- **Meridian subsystems (minimal forms):**
  - **SPIFFE CA:** must issue/verify the agent *node certificate* before ADS can require mTLS. Phase 3 bring-up may use a static dev mTLS pair; real coupling lands in Phase 4.
  - **Agent xDS client:** build an **in-memory agent stub** (speaks ADS, ACKs/NACKs, prints resources) — unblocks the entire control plane before real agents exist.
  - **eBPF map schema:** the compiler depends on the frozen `policy_key_t`/`policy_verdict_t` struct definitions, not on a running agent.
- **Bootstrap circularity:** the agent needs a cert to connect, and the connection issues certs — resolved by the shared node-bootstrap scheme in the [SPIFFE subsystem](04-spiffe.md#bootstrap-scheme).

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| 1 | **Policy compiler correctness** — selector expansion × ports × proto × default-deny can diverge from intent; PRD demands zero divergence | High / Critical | Write the **reference evaluator first** (naive, obviously-correct interpreter); property-test compiler ≡ reference over random tuples (pull PRD Phase 8 fuzzing forward as a *gate*); compilation total and deterministic; snapshot-test outputs |
| 2 | **xDS ACK/NACK and warming subtleties** — nonce mishandling, EDS-before-CDS, reconnect/out-of-order races → stale or wrong enforcement | High / High | Per-(node, type_url) state machine with explicit `lastSentNonce`/`lastAckedVersion`; strict dependency ordering; NACK = hold last-good + surface to `/status` + metric; conformance suite driving the stub through ACK/NACK/resubscribe/reconnect/out-of-order |
| 3 | **Numeric ID reuse** — a reused uint32 inheriting stale policy/EDS entries = silent cross-identity authorization | Med / Critical | Monotonic allocation, never reused within a control-plane lifetime; release = tombstone until reconcile confirms no references; EDS retraction pushed and ACKed before an IP may map to a new identity; audit every allocate/release |
| 4 | **Unavailability behavior** — partial snapshot on flap could regress enforcement to allow | Med / High | Whole-snapshot pushes per type_url with monotonic versions; agents atomically swap only fully-received ACKed snapshots; on restart rebuild full state from storage before treating any ACK as authoritative |
| 5 | **etcd consistency under churn** — watch lag/compaction yields stale snapshots | Med / High | Compute snapshots from a single consistent etcd revision; carry revision in `version_info`; memory backend as the deterministic oracle |
| 6 | **K8s informer races (Phase 7)** — pod IP reuse, delete/add reorder → wrong IP→identity binding | Med / High | Bind on podUID with IP as mutable attribute; EDS retraction on delete before any add reusing the IP |
| 7 | **go-control-plane impedance mismatch** | Med / Med | Spike both approaches; ADR by end of Phase 3 |

## Implementation order (PRD Phases 3 and 7)

- **CP-1: storage + identity + REST skeleton.** Storage interfaces + memory backend; identity registry with monotonic allocation + audit hooks; REST with schema validation. **Gate:** ID-allocation invariants unit-tested (no reuse); REST fails closed.
- **CP-2: policy compiler + reference evaluator.** Reference evaluator first; compiler → `policy_map` entries + L7 tables; property/fuzz harness. **Gate:** zero divergence over ≥ 1e6 random tuples; snapshot tests committed.
- **CP-3: ADS server vs the agent stub.** Stub agent; version/nonce state machine; dependency-ordered push on store Watch events; conformance suite. **Gate:** REST policy change visible in stub in < 500 ms (success criterion #4, measured).
- **CP-4 (Phase 4 coupling): mTLS on ADS.** Node-cert mTLS; `node.id` principal from peer SVID. **Gate:** unauthenticated stream rejected; node identity drives per-agent scoping.
- **CP-5 (Phase 7): etcd + Kubernetes.** etcd backend with revision-anchored snapshots; informers; CRD; optional webhook. **Gate:** informer race tests (IP reuse) pass; etcd and memory backends produce byte-identical compiled output for identical inputs.

Built entirely against fakes before real agents exist: CP-1..CP-3 (stub agent), the compiler (frozen struct defs), most of CP-5 (envtest/fake clientset).
