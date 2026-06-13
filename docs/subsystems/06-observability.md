# Subsystem 6 — Observability

> Ring-buffer flow pipeline, Prometheus metrics, OpenTelemetry traces, and the live CLI surfaces (`flows watch`, `http watch`, `network graph`). PRD Phases 0 (ring readback), 1 (basic metrics), 5 (full pipeline), 8 (drop-rate benchmark).

Observability has **two producers** (kernel ring buffer for L4 flow events; node proxy for L7 request records) and one logical pipeline that merges them. It runs inside the agent process but is specified as its own subsystem because its contracts — the `flow_event` layout, metric names/labels, and the flow-streaming API — are consumed by the CLI and external systems.

## Responsibilities

**Owns:**

1. **Ring buffer consumer.** Dedicated goroutine reading `flow_events` via `cilium/ebpf` ringbuf reader; decodes the canonical `flow_event` struct (bpf2go-generated — never hand-written); tracks its own drop counter (reserve failures + reader overruns).
2. **Aggregation.** Per-`(src_identity, dst_identity, dst_port)` byte/packet/flow counters; latency histograms (SOCKMAP `latency_ns`, proxy request latency); denied-flow log with reason (joining `denied_flows_map`).
3. **Identity name resolution.** Numeric ID → SPIFFE ID string for every human-facing output, using the identity table delivered via xDS. Unresolvable IDs render as `unknown(<id>)`, never dropped.
4. **Prometheus endpoint** (`:9901`). One registry for agent + proxy + pipeline metrics. Also sums `metrics_map` PERCPU counters on scrape.
5. **OpenTelemetry traces.** One span per L7 request proxied by the node proxy, exported via OTLP gRPC to the configured endpoint (Jaeger/Tempo/Datadog); W3C `traceparent` propagation.
6. **L4/L7 correlation.** Define the correlation key now — `(src_identity, dst_identity, dst_port)` + timestamp window — so `flows watch` and `http watch` reconcile into one coherent per-request view (cross-cutting decision CC-6).
7. **CLI streaming surfaces.** Server side of `meridian flows watch` (live ring-buffer tail with filters), `flows denied --since`, `http watch`, `network graph` (edges derived from the aggregation table), `map stats`.

**Not its job:** producing events (eBPF programs and proxy); long-term storage (Prometheus/Tempo are external); alerting; the CLI binary itself (Phase 6 — consumes this subsystem's streaming API); control-plane operational metrics (control plane self-reports).

## Interfaces

| Boundary | Direction | Peer | Form |
|---|---|---|---|
| `flow_events` ring buffer | consumer | eBPF | canonical 56-byte `flow_event`; bpf2go-generated decode |
| `metrics_map`, `denied_flows_map` | reader | eBPF | PERCPU sums on scrape; LRU dump for `flows denied` |
| L7 request records | consumer | node proxy | in-process channel / loopback gRPC: `{traceID, method, path, status, latency, srcID, dstID}` |
| Identity names | reader | agent xDS state | numeric ID → SPIFFE ID lookup table |
| Prometheus | server | scraper | `:9901`; metric names below |
| OTLP traces | exporter | OTLP receiver | gRPC to `tracing.otlp_endpoint` |
| Flow stream API | server | `meridian` CLI | gRPC server-streaming with src/dst/verdict filters |

**Metric naming contract (consumed by dashboards/tests — freeze early):**

```text
meridian_flows_total{src_identity, dst_identity, dst_port, verdict}
meridian_flow_bytes_total{src_identity, dst_identity, dst_port}
meridian_http_requests_total{src_identity, dst_identity, method, status}
meridian_http_request_duration_seconds{src_identity, dst_identity}   # histogram
meridian_ringbuf_dropped_events_total
meridian_policy_propagation_seconds                                   # success criterion #4 anchor
meridian_cert_expiry_timestamp_seconds{workload}
```

## Dependencies

- **Libraries:** `prometheus/client_golang`, `go.opentelemetry.io/otel` + OTLP trace exporter, `cilium/ebpf` ringbuf reader.
- **Contracts:** the canonical `flow_event` struct (eBPF subsystem, CC-5); the L7 record shape (node proxy); identity table (agent xDS state).
- **Minimal forms:** ring readback works in Phase 0 with the packet-counter program; full pipeline needs the Phase 1 maps; L7 spans need the Phase 5 proxy.

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| 1 | **Label cardinality explosion** — `(src_identity × dst_identity × port)` label sets can blow up Prometheus at scale | Med / High | Identities are bounded by service accounts (not pods) — document the bound; cap tracked pairs with an LRU + `meridian_flows_overflow_total`; no per-pod or per-IP labels ever |
| 2 | **Ring buffer overrun** — NFR < 0.1% drops at 1M pps | Med / Med | Decision-point events only (eBPF R6); batched reads on a dedicated goroutine; drop counters on both ends (kernel reserve failures + reader overruns); Phase 8 benchmark gates the NFR |
| 3 | **Struct decode drift** — C/Go `flow_event` divergence corrupts every event silently | Med / High | Single-source via bpf2go (CC-5); a round-trip decode test in CI fails the build on layout change |
| 4 | **Timestamp domain mismatch** — `bpf_ktime_get_ns` is monotonic-since-boot, not wall-clock; naive conversion skews traces and `--since` filters | Med / Med | Compute boot-time offset once at startup (`CLOCK_MONOTONIC` vs `CLOCK_REALTIME`), apply at decode; never compare raw kernel timestamps to wall-clock |
| 5 | **Trace context propagation gaps** — spans without a propagated `traceparent` fragment distributed traces | Low / Med | Propagate inbound `traceparent` through the CONNECT tunnel; generate a root span only when absent; verify parent-child linkage in the e2e demo |
| 6 | **Scrape-time PERCPU summing cost** | Low / Low | Cache sums with a short TTL; PERCPU reads are O(nCPU × entries), bounded |

## Implementation order

1. **O-1 (Phase 0) — Ring readback spine.** Consumer reads the packet-counter program's events. **Gate:** decoded fields match injected packets byte-for-byte (this is eBPF gate P0.2's userspace half).
2. **O-2 (Phase 1) — Flow metrics + denied log.** Aggregation table, Prometheus endpoint, `denied_flows_map` join, identity name resolution. **Gate:** `curl :9901/metrics` shows correct allow/deny counters for the netns integration test; denied flows carry SPIFFE names.
3. **O-3 (Phase 5) — Flow stream API.** gRPC server-streaming with filters; backs `meridian flows watch`. **Gate:** live tail shows allowed/denied flows in real time with identity names (success criterion #5).
4. **O-4 (Phase 5) — L7 pipeline.** Proxy record channel, OTLP exporter, `http watch` stream, L4/L7 correlation key. **Gate:** spans visible in an OTLP receiver with identity/status/latency; `http watch` shows per-request telemetry (success criterion #6).
5. **O-5 (Phase 8) — Load validation.** Drop-rate benchmark at 1M pps; cardinality stress at 10k identity pairs. **Gate:** < 0.1% drops; stable RSS within the agent's 50 MB budget.

Buildable in isolation: the aggregation table and metric registration (pure unit tests with synthetic events), the timestamp conversion, and the stream-API filtering.
