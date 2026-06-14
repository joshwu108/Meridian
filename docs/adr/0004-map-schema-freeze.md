# ADR-0004: Map-schema freeze (v2 maps + cross-boundary structs)

- **Status:** Accepted (Phase 1 exit gate, MER-34)
- **Date:** 2026-06-13
- **Tracking ticket:** MER-34
- **Relates to:** ROADMAP [CC-2](../ROADMAP.md#cross-cutting-decisions)
  (compiled-policy wire contract — **kernel half**), ARCHITECTURE D12–D17,
  ADR-0001 (D16 posture), ADR-0003 (D12 `policy_key`), MER-14 (contract
  land), MER-33 (schema single-sourcing). Consumed by every subsystem that
  reads or writes pinned maps after Phase 1; Phase 2 entry (MER-59) requires
  this ADR unchanged.
- **Provenance:** Number `0004` reserved by **MER-41**; full document authored
  at Phase-1 exit when gates P1.1, P1.2, P1.3, CP-2, and O-2 were green.

## Context

Phase 1 introduced policy enforcement, Geneve identity carriage, agent map
writers, and property-test harnesses that all depend on stable kernel/userspace
layouts. Phase 0 froze `flow_event` and the counter-era maps; Phase 1 (MER-14)
landed schema **v2** with `policy_key.direction`, `denied_flows_map`, and
`runtime_config_map`. Without a single exit-gate ADR, layout drift could
re-open silently across `tc_ingress`, `datapath.Writer`, the reference
evaluator, and the compiler.

This ADR is the **authoritative freeze** for:

1. Every **pinned** v2 map in `bpf/include/meridian_maps.h`
2. Every **cross-boundary** struct and enum in `bpf/include/meridian_types.h`
   (CC-6 / D9 — Go mirrors generated only via bpf2go `-type`)
3. The **`MERIDIAN_SCHEMA_VERSION` bump procedure** and fail-closed pin policy

The xDS / control-plane half of CC-2 (`pkg/wire` snapshot types) is out of
scope here but must stay consistent with the kernel layouts below via
`datapath.Writer` (D17).

## Decision

### Schema version

```c
enum meridian_schema_version {
    MERIDIAN_SCHEMA_VERSION = 2,
};
```

- Written to `schema_sentinel_map[0]` on **fresh** pin creation only; verified on
  every re-open (D15 / review D-9).
- Go reads the constant via bpf2go from the `Counter` object BTF — **never**
  hand-mirror the number (MER-33 / review D-1).
- **v1 pins are refused** (fail closed). Pre-GA upgrade path: wipe the pin
  directory under `/sys/fs/bpf/meridian/` (or the test subtree).

### Pinned maps (v2 freeze)

Pin root: `/sys/fs/bpf/meridian/` (tests: `/sys/fs/bpf/meridian-test/<run>/<test>/`).
All maps use `LIBBPF_PIN_BY_NAME`.

| Map | Type | Key → Value | max_entries | Writers → Readers |
|-----|------|-------------|-------------|-------------------|
| `flow_events` | RINGBUF | — → `struct flow_event` | 4 MiB (bytes, power of 2) | tc_in, tc_eg → agent consumer |
| `metrics_map` | PERCPU_ARRAY | `u32` metric_id → `u64` | 16 (`METRIC_ID_MAX`) | all progs → agent, CLI |
| `schema_sentinel_map` | ARRAY | `0` → `enum meridian_schema_version` | 1 | agent stamp/verify |
| `identity_map` | HASH, NO_PREALLOC | `u32` pod_ipv4 **BE** → `u32` identity **host** | 65536 | agent → tc_in, tc_eg, proxy, CLI |
| `policy_map` | HASH, NO_PREALLOC | `struct policy_key` → `struct policy_verdict` | 16384 | agent → tc_in, tc_eg, sock_ops (P2), CLI |
| `runtime_config_map` | ARRAY | `0` → `u32` flag bits | 1 | agent → tc_in, tc_eg |
| `denied_flows_map` | LRU_HASH | `struct flow_key` → `struct deny_info` | 4096 | tc_in, tc_eg → agent, CLI |

**Not instantiated in v2** (Phase 2 — specified in ARCHITECTURE §2 only):

| Map | Type | Key → Value | max_entries |
|-----|------|-------------|-------------|
| `sockhash` | SOCKHASH | `sock_key{dst_ip BE; dst_port BE; pad}` → sock | 65536 |

**Program-local maps** (not pinned, not part of this freeze): `udp_seen_flows_map`
in `tc_ingress.c` — LRU used for D13 UDP first-sight detection; eviction or layout
changes there do not require a schema bump.

### Cross-boundary structs and enums

Canonical header: `bpf/include/meridian_types.h`. Every layout has
`_Static_assert(sizeof …)` guards.

#### `struct flow_event` — 56 bytes (Phase 0 freeze, unchanged in v2)

| off | size | field | byte order |
|-----|------|-------|------------|
| 0 | 8 | `timestamp_ns` | host |
| 8 | 4 | `src_ip` | network |
| 12 | 4 | `dst_ip` | network |
| 16 | 2 | `src_port` | network |
| 18 | 2 | `dst_port` | network |
| 20 | 1 | `proto` | — |
| 21 | 1 | `verdict` | `enum flow_verdict` |
| 22 | 2 | `_pad0` | must be 0 |
| 24 | 4 | `src_identity` | host |
| 28 | 4 | `dst_identity` | host |
| 32 | 4 | `bytes` | host |
| 36 | 4 | `_pad1` | must be 0 |
| 40 | 8 | `latency_ns` | host |
| 48 | 2 | `l7_status_code` | host |
| 50 | 6 | `_pad2[3]` | must be 0 |

#### `struct policy_key` — 12 bytes (D12 / ADR-0003)

| off | size | field | byte order |
|-----|------|-------|------------|
| 0 | 4 | `src_id` | host (0 = unknown) |
| 4 | 4 | `dst_id` | host |
| 8 | 2 | `dst_port` | **host** (`bpf_ntohs` before lookup) |
| 10 | 1 | `proto` | IPPROTO_* |
| 11 | 1 | `direction` | `enum policy_direction` |

#### `struct policy_verdict` — 4 bytes (D4)

| off | size | field |
|-----|------|-------|
| 0 | 1 | `action` — `enum flow_verdict` |
| 1 | 1 | `flags` — bit 0 `SOCKMAP_ELIGIBLE`, 1 `L7_REQUIRED`, 2 `MTLS_REQUIRED`, 3 `AUDIT`; bits 4–7 reserved = 0 |
| 2 | 2 | `_pad` — must be 0 |

#### `struct flow_key` — 16 bytes (denied_flows_map key)

All IP/port fields **network** order; `_pad[3]` must be 0.

#### `struct deny_info` — 16 bytes (D14)

| off | size | field |
|-----|------|-------|
| 0 | 8 | `last_ns` |
| 8 | 4 | `count` |
| 12 | 4 | `reason` — `enum drop_reason` |

#### Supporting enums

- `enum flow_verdict` — ALLOW=0, DENY=1, REDIRECT=2
- `enum policy_direction` — INGRESS=0, EGRESS=1
- `enum drop_reason` — UNSPECIFIED, POLICY_DENY, POLICY_MISS, UNKNOWN_IDENTITY, INVALID_ACTION, GENEVE_ENCAP_FAIL (filling reserved values is compatible — no bump)
- `enum metric_id` — slots 0–7 assigned (see header); array sized to `METRIC_ID_MAX=16`

### Byte-order rule (binding)

Fields copied verbatim from packet bytes use **network** order (`flow_key`,
`flow_event` addresses/ports, `identity_map` key). Fields constructed by BPF or
userspace use **host** order (identity IDs, `policy_key.dst_port`). Mismatch
→ silent lookup miss, not a verifier error.

### bpf2go / codegen contract (D9, MER-14)

- Cross-boundary types are listed **once** on the `Counter` `//go:generate` line
  in `bpf/gen.go` (`-type flow_event -type policy_key … -type meridian_schema_version`).
- `tc_ingress.c` / `tc_egress.c` use **separate** bpf2go objects (`TcIngress`,
  `TcEgress`) without re-listing `-type` — Go code uses `Counter*` prefixed
  mirrors for shared structs until a combined collection lands (documented
  deviation; see below).
- `make ebpf` + committed `*_bpfel.{go,o}`; CI `make verify-gen` diffs.

### Agent update protocol (unchanged from ARCHITECTURE §2)

- Cross-map ordering: identity adds before policies referencing them; policy
  deletes before identity deletes.
- Snapshot apply: adds+modifies, then deletes (D5).
- Pads zeroed by zero-initializing structs before population.
- `datapath.Writer` is the **sole** wire→kernel translator (D17).

### `MERIDIAN_SCHEMA_VERSION` bump procedure

**Requires bump (fail closed on mismatch):**

- Any change to struct size, field order, or width of a pinned map key/value
- Adding or removing a **pinned** map
- Changing `max_entries` in a way that invalidates existing pins

**Steps when bumping (e.g. v2 → v3):**

1. Increment `MERIDIAN_SCHEMA_VERSION` in `meridian_types.h`.
2. Apply layout/map changes in `meridian_types.h` / `meridian_maps.h`.
3. Update `datapath.translate`, reference evaluator, and compiler if wire-visible.
4. `make ebpf`; commit regenerated bindings.
5. Extend T2 schema-sentinel tests (`test/bpf/schema_sentinel_test.go`).
6. Update this ADR and ARCHITECTURE §2; add an ADR row if the bump encodes a
   new cross-cutting decision.
7. Operator action pre-GA: **wipe** the bpffs pin directory — live migration is
   explicitly out of scope (D15).

**Compatible without bump:**

- New `drop_reason` or `metric_id` enum values within reserved slots
- New `policy_verdict.flags` bits 4–7 (must remain 0 in writers until assigned)
- Program-local map changes

**Runtime behavior on mismatch:**

- Fresh load → stamp sentinel with build version.
- Re-open, sentinel matches → continue.
- Re-open, sentinel = 0 → `ErrPartialPinSet` (crashed prior load).
- Re-open, sentinel ≠ build version → refuse to start (fail closed).

## As-built deviations (honest)

Recorded at MER-34 exit; not papered over:

1. **Per-program bpf2go objects** — Phase 0 recommended a single combined
   collection at Phase 1 freeze; as-built uses three objects (`Counter`,
   `TcIngress`, `TcEgress`) with shared types generated only under `Counter`.
   Rationale: smaller verifier iteration surface; merge deferred to Phase 2
   (`MER-47`).
2. **`sockhash` / `sock_key`** — specified in ARCHITECTURE §2 table but **not**
   present in `meridian_maps.h` until Phase 2 instantiation (MER-47).
3. **`udp_seen_flows_map`** — D13 UDP first-sight uses a program-local LRU in
   `tc_ingress.c`, not a pinned shared map; omitted from the freeze table above.
4. **REDIRECT / TPROXY** — `tc_ingress` marks SYN segments (`MERIDIAN_MARK_REDIRECT_PLACEHOLDER`); full TPROXY steering is Phase 4 (ADR-0006).
5. **Geneve / encap** — topology frozen in ADR-0002; encap-failure posture in
   ADR-0005. These ADRs consume this schema but are not duplicated here.

## Gate evidence (Phase 1 exit prerequisites)

All five upstream gates must be `armed=yes` with zero skips on kernel 5.15
(MER-44). Evidence: [`docs/PHASE1_GATE_EVIDENCE.log`](../PHASE1_GATE_EVIDENCE.log)
and CI workflow [`ci.yml`](../../.github/workflows/ci.yml).

| Gate | Ticket | Suite |
|------|--------|-------|
| P1.1 | MER-18 | `test/bpf/verdict_test.go` — `TestVerdictMatrixMatchesReferenceEvaluator` |
| P1.2 | MER-29 | `test/integration/policy_test.go` — `TestLivePolicyIntegrationGate_MER29` |
| P1.3 | MER-21 | `test/integration/geneve_test.go` — `TestGeneveIngressIdentityPolicyGate_MER21` |
| CP-2 | MER-24 | `internal/control/conformance_test.go` — `TestCompilerMatchesReferenceProperty` |
| O-2 | MER-32 | `test/integration/metrics_test.go` — `TestDeniedFlowsMetricsGate_MER32` |

## Consequences

- **Phase 2 entry (MER-59)** may proceed only after this ADR is Accepted and
  all five gates above are green. `sockhash` instantiation must not alter v2
  layouts without a schema bump.
- Any change to `bpf/include/meridian_{types,maps}.h` after this ADR requires
  either a compatible extension (no bump) or the full bump procedure — treated
  as a breaking change across agent, tests, and future control-plane ADS.
- D12–D17 outcomes are recorded as-built in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)
  decision log; open items not consumed by Phase 1 remain listed there.

## Rejected alternatives

1. **Versioned map names** (`policy_map_v2`) instead of sentinel — rejected at
   D6: doubles pin surface and complicates re-open.
2. **Hand-written Go struct mirrors** for kernel types — rejected at D9/CC-6:
   drift is silent; bpf2go is mandatory.
3. **In-place v1→v2 pin migration** — rejected at D15: pre-GA wipe is acceptable;
   migration machinery is YAGNI until GA customers exist.
