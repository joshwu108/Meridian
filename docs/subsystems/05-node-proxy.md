# Subsystem 5 — Node Proxy

> Per-node userspace Go proxy: mTLS termination/origination (15008 in / 15001 out), L7 HTTP policy, CONNECT tunneling between nodes, SVID consumption via the SPIFFE Workload API, L7 telemetry. PRD Phases 4–5.

## Responsibilities

**Owns:**

- **Inbound mTLS termination (15008).** Accept redirected inbound connections, present the destination workload's SVID, require and verify the client's SVID, enforce identity-based authz *before* any byte reaches the app.
- **Outbound mTLS origination (15001).** Accept redirected outbound connections, CONNECT-tunnel to the destination node's proxy:15008, establish peer-to-peer mTLS, stream app data through the tunnel. Source identity is carried by the client cert in the handshake, not an app-layer header.
- **L7 HTTP policy enforcement.** Parse HTTP/1.1 and HTTP/2 on L7-flagged connections; evaluate path/method/header rules; reject (403/RST_STREAM) before proxying.
- **SVID consumption.** `go-spiffe` `X509Source` against the agent's Workload API Unix socket; hot-swap certificates on rotation with zero dropped connections.
- **L7 telemetry.** Per-request OTel spans (OTLP gRPC) and Prometheus metrics: trace ID, latency, status, method, path, src/dst identity.
- **Circuit breaking** per upstream (consecutive-error threshold, half-open probe; PRD §4.8).

**Not its job:** the data path for L4-only flows — allowed passthrough and SOCKMAP flows never touch the proxy (this is the entire performance premise, PRD §4.5); signing or rotating certificates (agent + CA); authoring policy (arrives compiled via agent/xDS); discovering original destinations on its own (consumes the eBPF/TPROXY interface); WASM extensibility, UDP, Windows (non-goals).

## Interfaces

### Listeners

| Port | Role | Peer |
|---|---|---|
| 15008 | inbound mTLS server (`IP_TRANSPARENT` if TPROXY) | remote node proxy (CONNECT client) |
| 15001 | outbound intercept (`IP_TRANSPARENT` if TPROXY) | local pod's redirected outbound connection |
| 15000 | admin API | operator / CLI |

**Original-destination interface:** on every accepted connection, obtain `(orig_dst_ip, orig_dst_port)` plus eBPF-resolved identities — via `getsockname()` on the `IP_TRANSPARENT` socket (TPROXY) or a pinned `orig_dst_map` lookup. Abstract behind a single `originalDestination(conn) (netip.AddrPort, Identities, error)` so the mechanism can be swapped (CC-1).

### SPIFFE Workload API (consumed)

Standard SPIFFE Workload API gRPC over the agent's Unix socket (`FetchX509SVID` streaming). Use `go-spiffe/v2` `workloadapi.X509Source` → `tls.Config` via `GetCertificate`/`GetClientCertificate` plus a custom `VerifyPeerCertificate` checking the peer's SPIFFE URI SAN against authz policy. The source's watch loop delivers zero-downtime rotation.

### L7 policy (consumed)

Agent pushes immutable `[]CompiledL7Rule` snapshots keyed by `(dst_identity, listener)` (fetched via xDS LDS/RDS). Proxy holds them behind an atomically-swappable pointer — snapshot replace, never in-place mutation.

### Telemetry (produced)

- **OTLP gRPC traces** to `tracing.otlp_endpoint`: one span per proxied request (`src_identity`, `dst_identity`, method, path, status, latency; propagate W3C `traceparent`).
- **Prometheus**: request count/latency histograms per `(src_identity, dst_identity, status)`; circuit-breaker gauges. Register into the agent's `:9901` registry rather than opening a second listener.

## Dependencies

- **Go:** `spiffe/go-spiffe/v2`, stdlib `crypto/tls` + `golang.org/x/net/http2`, `go.opentelemetry.io/otel` + OTLP exporter, `prometheus/client_golang`, `go-chi/chi/v5`, `golang.org/x/sys/unix` (`IP_TRANSPARENT`).
- **Host:** TPROXY rule installed by the agent (or read access to pinned `orig_dst_map`).
- **Meridian subsystems (minimal forms):**
  - **eBPF redirect + orig-dst mechanism** — hard prerequisite; without it the proxy has nothing to accept.
  - **Agent Workload API socket** — minimal: serves one static SVID; full rotation validated incrementally.
  - **SPIFFE CA** — minimal: a self-signed intermediate that can mint two workload certs for an A→B test.
  - **Control plane L7 rules** — needed for Phase 5 only; mTLS pass-through (Phase 4) works with a hard-coded allow-all L7 table.

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| R1 | **Original-destination plumbing absent** — proxy cannot select an upstream; interception dead on arrival | High / Critical | Gate Phase 4 on a TPROXY (or `orig_dst_map`) prototype with an echo upstream *before* adding TLS; `originalDestination()` abstraction; e2e assertion on every redirected connection |
| R2 | **Hot-path latency** — handshake cost, allocations, goroutine churn vs the < 5% overhead NFR | Med / Med | Connection pooling / mTLS tunnel reuse between node proxies (never handshake per request); `sync.Pool` for buffers; precompiled O(1) L7 matchers; `wrk`/`hey` benchmarks + pprof on accept→upstream path |
| R3 | **HTTP/2 handling** — policy must be per-stream; a 403 must not tear down the connection; ALPN/HPACK pitfalls | Med / Med | Use `golang.org/x/net/http2`, never a hand-rolled frame parser; enforce at `http.Handler` level (per-stream RST_STREAM/403); `NextProtos = ["h2","http/1.1"]`; cap concurrent streams; test h1 and h2 clients |
| R4 | **Certificate rotation races** — mid-handshake swap or lagging trust bundle → spurious failures or accepting an expired peer | Low / Critical | `X509Source` atomic swap via callbacks (never mutate live `tls.Config`); verify against the current bundle on every handshake; chaos test: expired cert refused within rotation window |
| R5 | **SOCKMAP bypass surfacing as missing mTLS** (shared with eBPF R2) | Med / High | Instrument expected-vs-observed redirected-connection counts and alarm on divergence; real fix is `sock_ops` gating in the eBPF subsystem |
| R6 | **Authz scope confusion** — a valid mesh SVID is necessary, not sufficient | Low / High | Two-stage check: (1) chain/expiry/bundle validity, (2) `(src_id, dst_id)` against the authz table; deny by default; negative test: unauthorized service C with a valid SVID is rejected |

## Implementation order (PRD Phases 4–5)

1. **P4.1 — Redirect + orig-dst prototype (no TLS).** TPROXY → proxy → echo upstream. **Gate:** redirected connection reaches the proxy and the correct original destination is logged. De-risks R1 before any crypto.
2. **P4.2 — SVID consumption.** `X509Source` against the agent socket; `tls.Config` for server and client roles. **Gate:** valid SVID obtained; rotation swaps the cert with no restart.
3. **P4.3 — Inbound mTLS + peer verify + authz.** **Gate:** mutual auth completes; authorized identity allowed; unauthorized identity (valid SVID, wrong policy) rejected.
4. **P4.4 — Outbound CONNECT tunnel, end-to-end.** frontend → 15001 → CONNECT → remote 15008 → backend. **Gate:** full chain works with unchanged app semantics; cross-node overhead measured < 5% (success criteria 3 and 7).
5. **P5.1 — HTTP/1.1 + HTTP/2 L7 policy.** **Gate:** PRD §4.8 example enforced (`/api/` GET allowed, `/admin/` denied) for both h1 and h2.
6. **P5.2 — Circuit breaker.** **Gate:** opens after `consecutiveErrors`; half-open recovers.
7. **P5.3 — L7 telemetry.** **Gate:** OTLP spans appear in a receiver with identity/status/latency attributes (success criteria 5–6).

Buildable in isolation: L7 rule matcher (pure unit/fuzz vs reference), SVID/`tls.Config` rotation logic (local test CA, no eBPF), circuit-breaker state machine.
