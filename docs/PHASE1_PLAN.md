# Phase 1 Work Breakdown — TC Policy Engine

Scope (ROADMAP weeks 2–3): full TC parser + policy verdicts (eBPF P1.1–P1.3),
agent stub (A-1), flow metrics (O-2), reference evaluator + policy compiler +
fuzz harness (CP-2). Exit: **verdicts ≡ reference evaluator; map schemas frozen
(ADR)**. Carry-in from [PHASE0_REVIEW.md](PHASE0_REVIEW.md): debt items D-1, D-2,
D-3, D-5, D-6 are paid here by design, not as afterthoughts.

Owner roles (one person can hold several; see staffing mappings at the end):

| Role | Profile |
|---|---|
| **eBPF** | Kernel/C, verifier discipline, prog_test_run |
| **Agent** | Go systems: netlink, map writers, pinning, harness |
| **Platform** | Pure-Go correctness: evaluator, compiler, property testing |
| **Obs** | Telemetry: ring pipeline, Prometheus, aggregation |

---

## 1. Architecture updates (land via MER-14 and MER-34)

Deltas to `docs/ARCHITECTURE.md`; D12–D17 append to the decision log.

- **D12 — `policy_key` gains a direction field.** Phase 0 review P-1/D-5: the key
  becomes `{__u32 src_id; __u32 dst_id; __u16 dst_port; __u8 proto; __u8 direction}`
  (direction: 0=ingress, 1=egress — replaces the PRD's dead `pad` byte, so the
  size stays 12 and the agent's zero-the-pad rule becomes set-the-direction).
  Mirrored in `wire.PolicyRuleKey`. Recorded as **ADR-0003**.
- **D13 — Decision-point emission replaces per-packet emission.** `tc_ingress`
  emits `flow_event` only on: connection-open (TCP SYN, or first sight of a UDP
  flow via `denied/seen` LRU), DENY, and REDIRECT. Per-packet/byte totals move to
  `metrics_map` (`METRIC_BYTES_TOTAL`, `METRIC_FLOWS_ALLOWED/DENIED/REDIRECTED` —
  reserved slots 2–5 activate). `counter.c` stays as a Phase 0 artifact for
  toolchain tests but detaches from the production path.
- **D14 — `denied_flows_map`**: `LRU_HASH`, 4096 entries,
  `struct flow_key {__u32 src_ip, dst_ip; __u16 src_port, dst_port; __u8 proto; __u8 _pad[3];}`
  → `struct deny_info {__u64 last_ns; __u32 count; __u32 reason;}`. Debug/join
  surface only — never policy input.
- **D15 — Schema version 2.** New cross-boundary structs (`policy_key`,
  `policy_verdict`, `flow_key`) bump `MERIDIAN_SCHEMA_VERSION` to 2. Sentinel
  policy: an agent finding v1 pins **fails closed** (operator wipes the pin dir —
  acceptable pre-GA; live-migration machinery is explicitly out of scope).
  The Go literal mirror is deleted: the version is exported through bpf2go
  (`enum meridian_schema`) per review D-1.
- **D16 — Unknown-identity posture wired as built** (per ADR-0001 from MER-11):
  the `FALLOPEN_UNKNOWN` map-config flag and attach ordering (seed
  `identity_map` before TC attach) become code, with both postures covered by
  permanent T2 tests.
- **D17 — wire↔kernel translation boundary.** `datapath.Writer` is the **sole**
  translator from `pkg/wire` types to bpf2go types (review D-2). A T1
  equivalence test pins flag bits and key fields; depguard gains a rule that
  only `internal/agent/datapath` may import both `pkg/wire` and `bpf`.
- **Package graph changes:** `internal/agent/{attach,datapath}` and
  `internal/reference`, `internal/control` (compiler only) graduate from stub to
  implementation; new `internal/agent/metrics` (per-CPU reader + Prometheus).
- **Dependencies unlocked** (already version-pinned in go.mod comments):
  `vishvananda/netlink v1.3.0` (MER-25), `prometheus/client_golang v1.20.0` (MER-30).

## 2. Implementation tickets

All tickets ≤ 4h. ∥ Wave = tickets in the same wave run concurrently;
different lanes never block each other except where Deps say so.

| ID | Ticket | Owner | Est | Dependencies | Files touched | Wave |
|----|--------|-------|-----|--------------|---------------|------|
| MER-14 | **Phase 1 contract freeze**: `policy_key`/`policy_verdict`/`flow_key`/`deny_info` C structs + static asserts; `identity_map`/`policy_map`/`denied_flows_map` defs; `MERIDIAN_SCHEMA_VERSION 2`; `wire.PolicyRuleKey.Direction`; bpf2go `-type` additions; ADR-0003 (D12) | eBPF + Agent (pair) | 3–4h | Phase 0 exit | `bpf/include/meridian_types.h`, `meridian_maps.h`, `bpf/gen.go`, `pkg/wire/policy_snapshot.go`, `docs/adr/0003-policy-key.md`, `docs/ARCHITECTURE.md` | **0** |
| MER-15 | **wire↔C equivalence tests + depguard wall** (review D-2/D17): assert `wire.PolicyFlags` bits ≡ generated `policy_verdict.flags`, key field mapping, sizes | Platform | 2h | MER-14 | `internal/agent/datapath/translate_test.go`, `.golangci.yml` | 2 |
| MER-16 | **`tc_ingress.c`: parser + identity resolution**: eth/IPv4/L4 parse (counter.c lineage), src/dst `identity_map` lookups, unknown-identity posture per ADR-0001; loads verifier-clean | eBPF | 3–4h | MER-14 | `bpf/tc_ingress.c` (new), `bpf/gen.go`, generated bindings | 1 |
| MER-17 | **Verdict enforcement + decision-point emission** (D13): `policy_map` lookup, ALLOW→`TC_ACT_OK`, DENY→`TC_ACT_SHOT`+`denied_flows_map`+event, REDIRECT placeholder (mark only — TPROXY is Phase 4); SYN-only/deny-only event emission; metrics slots 2–5 | eBPF | 3–4h | MER-16 | `bpf/tc_ingress.c`, `bpf/counter.c` (demote), generated bindings | 2 |
| MER-18 | **P1.1 gate — T2 verdict matrix ≡ reference evaluator**: table-driven `prog_test_run` over allow/deny/redirect/unknown-identity/malformed/IPv6-passthrough, every case asserted against `reference.Evaluator` | eBPF + Platform (pair) | 3–4h | MER-17, MER-22 | `test/bpf/verdict_test.go` (new), `test/bpf/packets.go` (synth-packet builders extracted) | 4 |
| MER-19 | **Parser negative/regression T2 suite** (review T-3/T-4): truncated frames, `ihl<5`, VLAN, non-IPv4; ring-record byte assertions incl. zeroed pads | eBPF (delegable) | 2–3h | none (runs vs `counter.c` now, extends to `tc_ingress` after MER-17) | `test/bpf/malformed_test.go`, `test/bpf/ringbytes_test.go` (new) | 1 |
| MER-20 | **`tc_egress.c` + Geneve identity option push**: egress parse, option body = `src_identity` (CC-3) | eBPF | 3–4h | MER-17 | `bpf/tc_egress.c` (new), `bpf/gen.go`, `bpf/include/meridian_consts.h` (Geneve consts) | 3 |
| MER-21 | **P1.3 gate — Geneve ingress parse + two-node test**: `tc_ingress` consumes carried `src_identity` for non-local IPs; two-"node" netns test enforces policy on the remote identity (placement per ADR-0002) | eBPF | 4h | MER-20, MER-28 | `bpf/tc_ingress.c`, `test/integration/geneve_test.go` (new) | 4 |
| MER-22 | **Reference evaluator implementation**: pure-Go oracle for `(src,dst,port,proto,direction) → verdict`, first-class unknown-identity handling; exhaustive unit tests | Platform | 3–4h | MER-14 (Direction field) | `internal/reference/evaluator.go` (new), `evaluator_test.go` | 1 |
| MER-23 | **Policy compiler**: declarative policy model → `[]wire.PolicyRule`; deterministic output ordering; snapshot tests | Platform | 4h | MER-22 | `internal/control/compiler.go` (new), `compiler_test.go`, `pkg/wire/policy.go` (declarative model, new) | 2 |
| MER-24 | **CP-2 gate — compiler ≡ reference property harness**: randomized tuples, zero divergence over ≥1e6 cases (full run nightly, 1e4 in PR CI); corpus committed | Platform | 3–4h | MER-23 | `internal/control/conformance_test.go` (new), `.github/workflows/ci.yml` (nightly job) | 3 |
| MER-25 | **`attach.Manager` netlink implementation**: qdisc replace + BPF filter add (direct-action) via `vishvananda/netlink`; unpin-or-replace program pin (review P-3/D-6); wires `--iface` into the agent (review F-3 made real product code) | Agent | 3–4h | none | `internal/agent/attach/manager_linux.go` (new), `cmd/meridian-agent/main.go`, `go.mod` | 1 |
| MER-26 | **`datapath.Writer` implementation**: `CommitPlan` apply with **adds-before-deletes** (D5); wire→bpf2go translation (sole translator, D17); direction byte set; idempotent re-apply | Agent | 4h | MER-14 (+ regenerated bindings) | `internal/agent/datapath/writer_linux.go` (new), `translate.go`, `writer_test.go` (fake-map T1) | 2 |
| MER-27 | **A-1 agent stub**: static YAML → `wire.PolicySnapshot` → diff → `CommitPlan`; seed-maps-before-attach ordering (D16); pin re-open restart survival | Agent | 3–4h | MER-26 | `internal/agent/config/yaml.go` (new), `cmd/meridian-agent/main.go`, `internal/agent/supervisor/` (minimal runner), example config in `test/integration/testdata/` | 3 |
| MER-28 | **Harness growth — two-node topology + seeding + traffic helpers**: second veth pair with routing (Geneve link per ADR-0002), `identity_map`/`policy_map` seed helpers, `nc`-based allow/deny assertions | Agent (delegable) | 4h | none (builds against Phase 0 fixtures) | `test/harness/twonode.go` (new), `test/harness/seed.go` (new), `test/harness/netns.go` | 1 |
| MER-29 | **P1.2 gate — live policy integration test**: agent stub end-to-end — allowed `nc` succeeds, denied drops, flipping a `policy_map` entry takes effect immediately, `denied_flows_map` records the drop, agent restart preserves enforcement | Agent | 4h | MER-17, MER-25, MER-26, MER-27, MER-28 | `test/integration/policy_test.go` (new) | 4 |
| MER-30 | **Metrics reader + Prometheus endpoint**: per-CPU summing package (kills the test `sumPercpu` duplication, review D-3/A-2); `/metrics` on :9901 serving `metrics_map` counters | Obs | 3h | none | `internal/agent/metrics/reader_linux.go` (new), `prometheus.go` (new), `reader_test.go`, `go.mod`, test de-dup in `test/bpf/`, `test/integration/` | 1 |
| MER-31 | **Flow aggregation + identity name resolution**: ring events → allow/deny/bytes by identity-pair; `identitytable.Resolver` impl backed by the stub YAML; labels carry SPIFFE names | Obs | 3–4h | MER-14, MER-30 | `internal/agent/telemetry/aggregate.go` (new), `internal/agent/identitytable/yaml.go` (new), tests | 2 |
| MER-32 | **O-2 gate — denied-flows join + metrics assertion**: `denied_flows_map` reader joined with identity names; integration test curls `:9901/metrics` during MER-29's scenario and asserts correct allow/deny counters | Obs | 3h | MER-29, MER-31 | `internal/agent/metrics/denied.go` (new), `test/integration/metrics_test.go` (new) | 5 |
| MER-33 | **Schema version single-sourcing** (review D-1): export version via bpf2go enum, delete the Go literal in the loader; fail-closed test for v1-pins-meet-v2-agent (review T-2 finally lands) | Agent or Obs | 2h | MER-14 | `bpf/include/meridian_types.h`, `internal/agent/bpfobj/loader_linux.go`, `loader_test.go` (T2, new) | 2 |
| MER-34 | **Exit gate — ADR-0004 map-schema freeze + doc reconciliation**: freeze all v2 map schemas/structs (CC-2 kernel half); append D12–D17 outcomes as-built; update README/checklist | eBPF + all (review) | 2h | MER-18, MER-21, MER-24, MER-29, MER-32 | `docs/adr/0004-map-schema-freeze.md`, `docs/ARCHITECTURE.md`, `README.md` | 6 |

**Total ≈ 66–74h.** Gates: P1.1 = MER-18 · P1.2 = MER-29 · P1.3 = MER-21 ·
CP-2 = MER-24 · O-2 = MER-32 · schema freeze = MER-34.

## 3. Parallelization plan

**The single serialization point is MER-14** (the contract freeze). It is
deliberately small (one pairing session, first morning) — after it lands and
`make ebpf` regenerates bindings, all four lanes run free. MER-19, MER-25,
MER-28, MER-30 have **zero dependencies** and can even start before MER-14.

```text
Wave 0  ──  MER-14 (everyone reviews; eBPF+Agent pair-write)          [½ day]
            └─ pre-starters with no deps: MER-19 · MER-25 · MER-28 · MER-30

Wave 1  ──  eBPF: MER-16        Platform: MER-22
            Agent: MER-25→28    Obs: MER-30                            [day 1–2]

Wave 2  ──  eBPF: MER-17        Platform: MER-23 (+MER-15)
            Agent: MER-26        Obs: MER-31 (+MER-33)                 [day 2–3]

Wave 3  ──  eBPF: MER-20        Platform: MER-24
            Agent: MER-27                                              [day 3–4]

Wave 4  ──  eBPF+Platform: MER-18 (P1.1 ✓)    eBPF: MER-21 (P1.3 ✓)
            Agent: MER-29 (P1.2 ✓)                                     [day 4–6]

Wave 5  ──  Obs: MER-32 (O-2 ✓)                                        [day 6]
Wave 6  ──  All: MER-34 (schema freeze ✓ → Phase 2 entry)              [day 6–7]
```

**Critical path** (≈ 21–24h): MER-14 → MER-16 → MER-17 → MER-29 → MER-32 → MER-34.
The eBPF verdict chain (16→17) and the agent chain (26→27) converge at MER-29;
keep both moving in parallel so neither waits at the join.

**Staffing mappings:**

- **4 people** (one per role): the wave diagram as drawn; ~6–7 working days,
  matching the ROADMAP's weeks 2–3 with slack for verifier debugging (the
  schedule-risk reserve sits in MER-17/18, same risk class as Phase 0's MER-6).
- **2 people** (ROADMAP workstreams A/B): A takes eBPF+Agent lanes
  (14→16→25→17→26→27→20→29→21), B takes Platform+Obs
  (22→23→30→24→31→15→33→32). ~2 weeks; the only cross-handoff points are
  MER-18 (pair) and MER-34.
- **1 person**: follow the critical path, interleaving MER-22 before MER-18;
  defer MER-20/21 (P1.3) to the tail. ~9–10 days.

**Rules that keep the parallelism safe:**

1. Nobody edits `bpf/include/meridian_*.h` after MER-14 without an explicit
   re-freeze (it invalidates every lane's generated bindings).
2. `datapath.Writer` is the only wire→kernel translator (D17); Platform codes
   against `pkg/wire` only, eBPF against the C headers only.
3. Every lane lands T1/T2 tests in the same PR as its code — Phase 0's review
   showed what merging untested batches costs.
4. Regenerated bindings (`make ebpf`) are committed by the ticket that changes
   the C, never by a consumer ticket.
