# Phase 2 Implementation Tickets — SOCKMAP Redirect + ADS Conformance

Derived from [PHASE2_PLAN.md](PHASE2_PLAN.md) (same IDs). Format follows
[PHASE1_TICKETS.md](PHASE1_TICKETS.md): every ticket ≤ 4h, acceptance criteria
are testable, **Wave** marks tickets that run concurrently. Owner roles per the
plan: eBPF · Agent · Platform.

**Entry gate:** no ticket in this file may merge until **MER-34** (Phase-1
exit) is green. See [PHASE2_GATES.md](PHASE2_GATES.md) and
[ROADMAP.md](../ROADMAP.md).

| ID | Ticket | Owner | Est | Acceptance criteria | Deps | Files expected to change | Wave |
|----|--------|-------|-----|---------------------|------|--------------------------|------|
| MER-47 | **Phase 2 contract land** | eBPF + Agent (pair) | 2–3h | `sockhash` map defined in `meridian_maps.h` (`BPF_MAP_TYPE_SOCKHASH`, `sock_key` key, pinned `LIBBPF_PIN_BY_NAME`); `sock_ops.c` and `sk_msg.c` compile verifier-clean as no-op/skeleton programs; both listed in `bpf/gen.go` with `sock_key` in `-type`; `make ebpf` regenerates bindings committed; D18 recorded in ARCHITECTURE decision log | **Phase-2 entry** (MER-34 green) | `bpf/include/meridian_maps.h`, `bpf/sock_ops.c` (new), `bpf/sk_msg.c` (new), `bpf/gen.go`, generated bindings, `docs/ARCHITECTURE.md` | **0** |
| MER-48 | **`sock_ops.c`: gated SOCKHASH population (P2.1 core)** | eBPF | 3–4h | On `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` and `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`, program resolves `(src_id, dst_id, dst_port, proto, direction)` and looks up `policy_map`; calls `bpf_sock_hash_update()` **only** when verdict has `POLICY_FLAG_SOCKMAP_ELIGIBLE` (CC-5); all other verdicts leave SOCKHASH untouched; loads verifier-clean on 5.15; T2 `prog_test_run` or cgroup attach smoke proves an eligible flow's socket is present after connect | MER-47 | `bpf/sock_ops.c`, `bpf/include/meridian_helpers.h` (new) | 1 |
| MER-49 | **P2.1-N GATE — permanent SOCKMAP-negative test (CC-5 / eBPF R2)** | eBPF + Platform (pair) | 3–4h | Table-driven T2/T3 suite: for each non-eligible verdict class — DENY, ALLOW+`L7_REQUIRED`, ALLOW+`MTLS_REQUIRED`, REDIRECT, ALLOW without `SOCKMAP_ELIGIBLE` — a synthetic connect/establish path asserts the socket is **absent** from `sockhash` (map iteration or `bpf_map_lookup_elem` from a helper program); eligible ALLOW+`SOCKMAP_ELIGIBLE` control case asserts presence; zero skips; manifest row `armed=yes`; test name stable for MER-44 | MER-48, MER-22 | `test/bpf/sockmap_negative_test.go` (new), `test/gates/manifest.txt`, `docs/PHASE2_GATES.md` | 2 |
| MER-50 | **`sk_msg.c`: redirect + fall-through + `latency_ns`** | eBPF | 3–4h | On `sendmsg`, looks up `(dst_ip, dst_port)` in `sockhash`; on hit calls `bpf_msg_redirect_map()` to peer socket; on miss returns `SK_PASS` (normal kernel path); records `latency_ns` in `flow_event` on redirect path (decision-point emission per D13); increments `METRIC_FLOWS_REDIRECTED` (or dedicated sockmap slot); loads verifier-clean; T2 smoke: redirect returns `SK_REDIRECT` for a seeded sockhash entry | MER-48 | `bpf/sk_msg.c`, `bpf/include/meridian_consts.h`, generated bindings | 2 |
| MER-51 | **P2.2 GATE — byte integrity + denied never redirected** | eBPF + Agent (pair) | 4h | T3 test on two-pod-same-node topology: eligible flow transfers ≥1 MiB payload byte-for-byte identical to a baseline plain-TCP run (no corruption, no truncation); flipping policy to DENY mid-test causes subsequent sends to **not** redirect (fall through or fail per stack); denied flow never completes via SOCKMAP path; suite green on 5.15 with agent attaching sock_ops/sk_msg (MER-57) | MER-50, MER-57 | `test/integration/sockmap_integrity_test.go` (new), `test/gates/manifest.txt` | 4 |
| MER-52 | **P2.2-BENCH — intra-node latency measurement** | eBPF | 2–3h | T4 (`e2e` tag) benchmark: same-node eligible flow with SOCKMAP vs without; reports p50/p99 connect+first-byte latency; documents ≥ measurable win or flags "no win on 5.15-azure" with numbers; runs nightly/self-hosted only (not PR gate); results committed as `test/integration/testdata/sockmap_bench.json` or CI artifact | MER-51 | `test/integration/sockmap_bench_test.go` (new) | 5 |
| MER-53 | **CP-1 slice: memory store + identity registry + REST skeleton** | Platform | 4h | `memory` backend implements `control.Store`; identity registry allocates monotonic uint32 IDs (CC-3: never reused within process lifetime); REST serves `POST/GET /policies`, `POST/GET /services`, `GET /status` with schema validation and fail-closed errors; `meridian-control` binary starts and accepts REST; unit tests cover ID allocation invariants and REST 4xx on bad input | **Phase-2 entry** | `internal/control/store/memory.go` (new), `internal/control/identity/registry.go` (new), `internal/control/rest/server.go` (new), `internal/control/rest/server_test.go` (new), `cmd/meridian-control/main.go` | 1 |
| MER-54 | **ADS server: version/nonce state machine + ordered push** | Platform | 4h | `StreamAggregatedResources` bidirectional handler; per-(node, type_url) `version_info` + `nonce` bookkeeping; ACK advances accepted version, NACK holds last-good; push ordering: CDS before EDS, LDS before RDS; store `Watch()` triggers recompute+push; malformed resource → NACK with `error_detail`; T1 state-machine tests cover ACK/NACK/stale-nonce/resubscribe | MER-53 | `internal/control/ads/server.go` (new), `internal/control/ads/versioning.go` (new), `internal/control/ads/server_test.go` (new), `go.mod` | 2 |
| MER-55 | **ADS agent stub (in-memory xDS client)** | Platform | 3–4h | Stub speaks ADS over loopback gRPC (in-process or `bufconn`); subscribes to CDS/EDS/LDS/RDS; ACKs after decoding resources; NACKs on contract violation; prints/logs received snapshot for debugging; T1 test drives stub through connect → receive → ACK → reconnect cycle | MER-54 | `internal/control/ads/stub_agent.go` (new), `internal/control/ads/stub_agent_test.go` (new) | 3 |
| MER-56 | **CP-3 GATE — ADS conformance + <500 ms propagation** | Platform | 4h | Conformance suite drives stub through: initial snapshot, policy add, policy delete, NACK recovery, out-of-order nonce ignore, reconnect with last-known version; REST `POST /policies` → stub receives updated compiled resources in **< 500 ms** (measured with `WaitUntil`, not sleep); zero skips; manifest `armed=yes`; regression seeds committed | MER-55 | `internal/control/ads/conformance_test.go` (new), `internal/control/ads/testdata/` (new), `test/gates/manifest.txt` | 4 |
| MER-57 | **Agent cgroup + SOCKHASH attach path** | Agent | 3–4h | `attach.Manager` (or sibling) attaches `sock_ops` to cgroup v2 fd and `sk_msg` to sockhash map fd (`BPF_SK_MSG_VERDICT`); idempotent `EnsureAttached`/`Detach`; T3 smoke: agent starts with `--iface` + `--cgroup` flags, programs listed in `bpftool prog show`; D19/D20 recorded | MER-47 | `internal/agent/attach/cgroup_linux.go` (new), `internal/agent/attach/sockmap_linux.go` (new), `internal/agent/attach/cgroup_test.go` (new), `cmd/meridian-agent/main.go` | 2 |
| MER-58 | **`bpfobj` loader: sock_ops/sk_msg + sockhash re-open** | Agent | 2–3h | Loader opens/reopens pinned `sockhash` alongside Phase-1 maps; loads sock_ops/sk_msg collection; restart test: kill agent, restart, sockhash entries survive (pin re-open, not recreate); T2 test in `loader_test.go` | MER-47, MER-57 | `internal/agent/bpfobj/loader_linux.go`, `internal/agent/bpfobj/loader_test.go` | 3 |
| MER-59 | **EXIT GATE — Phase-2 doc reconciliation + Phase-3 entry** | eBPF + all (review) | 2h | [PHASE2_GATES.md](PHASE2_GATES.md) lists all gates green with CI links; README status updated to Phase 2 complete; ROADMAP week-4 exit criteria checked off; ARCHITECTURE D18–D20 recorded as-built; Phase-3 entry rule stated (MER-59 green + ADR-0004 frozen schemas unchanged) | MER-49, MER-51, MER-56, MER-52 | `docs/PHASE2_GATES.md`, `README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md` | 6 |

## Dependency graph / schedule

```text
[ENTRY] Phase-2 entry = MER-34 green (Phase-1 exit)

Wave 0 (serialization point): MER-47
  parallel after entry: MER-53 (Platform, no eBPF dep)

Lane eBPF:     MER-47 → MER-48 → MER-49* ∥ MER-50 → MER-51* → MER-52
Lane Agent:    MER-47 → MER-57 → MER-58
Lane Platform: MER-53 → MER-54 → MER-55 → MER-56*

Joins: MER-51 ← {50, 57} · MER-59 ← {49, 51, 56, 52}
```

- **Critical path ≈ 18–22h**: MER-47 → MER-48 → MER-50 → MER-51 → MER-59.
- **Gates**: P2.1-N = MER-49 · P2.2 = MER-51 · P2.2-BENCH = MER-52 ·
  CP-3 = MER-56 · **Phase 2 exit / Phase 3 entry** = MER-59.
- **CC-5 invariant** is enforced by MER-49 (permanent negative test) and
  compile-time rejection in MER-22/23 — both must stay green in CI.
- Staffing variants and parallel-safety rules are in
  [PHASE2_PLAN.md §3](PHASE2_PLAN.md).
