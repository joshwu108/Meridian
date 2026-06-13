# Meridian Architecture

Merged output of the four design workstreams (TC ingress, eBPF map schema, agent internals, integration test environment) plus the Phase 0 build-pipeline decisions. Subsystem-level responsibilities/risks live in [docs/subsystems/](subsystems/); the [ROADMAP](../ROADMAP.md) holds sequencing. This document holds the **contracts and mechanisms**.

## Decision log

Decisions made during design; each was open in the PRD or ROADMAP (CC-x references):

| # | Decision | Rationale |
|---|---|---|
| D1 | **TPROXY + `IP_TRANSPARENT`** for original-destination recovery (CC-1). `tc_ingress` marks (never `bpf_redirect`s) proxy-bound connections; agent installs `ip rule fwmark → local` + mangle TPROXY; proxy recovers dst via `getsockname()`. **No orig-dst map in v1.** | `bpf_redirect*` loses the original dst; TPROXY matches Istio ztunnel and avoids a hot-path LRU map |
| D2 | **SYN-only marking** for proxy redirect: mark only `syn && !ack` TCP segments. | Connection-level property; stateless (no conntrack); steering binds at the SYN |
| D3 | **Proxy re-resolves identities** from `identity_map` (it has read access) instead of a kernel-written per-connection context map. | One userspace lookup per connection vs a per-SYN map write on the hot path |
| D4 | `l7_required` lives in **`policy_verdict.flags` bit 1**, not in `action`. `action` = {ALLOW=0, DENY=1, REDIRECT=2}; flags = orthogonal booleans (bit 0 `SOCKMAP_ELIGIBLE`, bit 1 `L7_REQUIRED`, bit 2 `MTLS_REQUIRED`, bit 3 `AUDIT`; bits 4–7 reserved, must be 0). | Removes the PRD's action/l7 redundancy; sockmap gating needs an explicit bit (CC-5) |
| D5 | **Policy snapshot application: adds/modifies before deletes** on the live flat HASH (no double-buffer map-of-maps). | Live set stays bounded by `C ∪ D`: no transient allow that neither old nor new policy permits; deletes-first causes transient false denies |
| D6 | **Schema sentinel map** (`schema_sentinel_map`, ARRAY[1] = `MERIDIAN_SCHEMA_VERSION`) instead of versioned map names. Agent re-opens pins only on version match; refuses to start on a newer version (fail closed). | One syscall at startup; keeps "re-open, never re-create" simple |
| D7 | **Fake-clock injection** (not short TTLs) for all certificate-expiry testing. Requires a clock seam in the SVID rotation scheduler and CA. | Deterministic boundary coverage (2/3-TTL, expiry instant); no flaky timeouts |
| D8 | **Identity value width = `__u32`** (resolves PRD §4.3's 8 B vs §6.3's 4 B); ID 0 reserved = unknown; control plane is sole allocator, monotonic, never reused (CC-3). | Geneve option carries it cluster-globally; 4 B suffices |
| D9 | **bpf2go single-sourcing**: every cross-boundary struct defined once in `bpf/include/meridian_types.h`; Go mirrors generated with `-type`; hand-written wire structs are a contract violation (CC-6). | Eliminates the PRD's C/Go `flow_event` drift by construction |
| D10 | **Pinned clang 17**, `-O2 -g -Wall -Werror -target bpfel -mcpu=v3 -Iinclude`; generated bindings + `vmlinux.h` committed; CI `verify-gen` diffs after regeneration. | `-O2` is verifier-mandatory; pinned compiler makes committed output stable |
| D11 | Module path `github.com/joshuawu/meridian`; **minimal go.mod**, deps added by the phase that first imports them (versions pinned in comments from PRD §13). | YAGNI; avoids 40 unused transitive modules in security scans |
| D12 | **`policy_key` carries an explicit `direction` byte** (0=ingress, 1=egress) replacing v1's pad — same 12-byte size; every compiled rule is direction-explicit (a "both ways" policy compiles to two entries). Part of schema v2. See [ADR-0003](adr/0003-policy-key.md). | Separate ingress/egress TC programs need direction-aware rules; wildcard or dual-map alternatives cost hot-path lookups or map sprawl |

**Still open** (each needs an ADR before the phase that consumes it): unknown-identity posture (fail-open passthrough vs default-deny-on-attach — skeleton keeps a one-constant `FALLOPEN_UNKNOWN` toggle; recommendation: default-deny once the agent populates `identity_map` before TC attach); Geneve parse placement relative to kernel decap (the biggest unresolved data-path detail); `dst_port` endianness is **host order** in `policy_key` (pinned below) — compiler must match; where remote-dst egress L4 policy is enforced (recommendation: destination node, inbound-authoritative); egress encap-failure policy (drop vs pass-unencapsulated).

---

## 1. TC ingress architecture

### Processing pipeline (per packet)

1. **Ethertype gate** — bounds-check `ethhdr`; non-IPv4 (incl. IPv6, ARP) → `TC_ACT_OK` + counter. Malformed → `TC_ACT_OK` + `MALFORMED` counter (a dropped malformed frame would be a silent DoS vector; malformed ≠ policy decision).
2. **IPv4 parse** — validate fixed header, `ihl ∈ [5,15]`, options inside `data_end`. L4 offset is `ip + ihl*4` (**the PRD skeleton's `(ip+1)` is a bug** — wrong with IP options).
3. **Identity resolution** — local path: `src_id`/`dst_id` from `identity_map`; tunnel path: `src_id` from the Geneve identity option (remote IPs aren't in the local map), `dst_id` from `identity_map`. Miss → `FALLOPEN_UNKNOWN` posture (open question above).
4. **L4 parse** — bounds-checked TCP/UDP ports; capture `syn && !ack` for D2/telemetry.
5. **Policy lookup** — `policy_key{src_id, dst_id, dst_port, proto, direction}` (D12: ingress program looks up with `POLICY_DIR_INGRESS`); **miss = deny** (default-deny, PRD §8). `direction` must be a valid enum value — HASH compares full key bytes.
6. **Verdict dispatch** — ALLOW → `TC_ACT_OK`; DENY → `TC_ACT_SHOT` + `denied_flows_map` + event; REDIRECT → on SYN only, `skb->mark |= TPROXY_MARK` (OR, preserve other bits) then `TC_ACT_OK` — steering happens in the netfilter mangle path (D1). Unrecognized action → fail closed `TC_ACT_SHOT`.
7. **Telemetry** — never changes the verdict, never blocks; `bpf_ringbuf_reserve` failure increments a drop counter.

### Verifier strategy

- Bounds-check every header pointer against `data_end` after it is computed; re-derive after every advance (the verifier doesn't carry ranges across unverified arithmetic).
- Geneve TLV walk: `#pragma unroll` with hard cap `MAX_GENEVE_OPTS = 4`; per-iteration bounds checks make attacker-controlled lengths abort the walk ("option absent" fallback, `src_id = 0`).
- `flow_event` is ring-allocated (`reserve`/`submit`), consuming zero stack; residents stay well under the 512 B frame.
- No tail calls in v1 — single bounded straight-line path; a per-protocol `prog_array` after stage 2 is the natural split if ever needed (YAGNI).
- `bpf_prog_test_run` in CI on the exact target kernel; verifier logs kept as artifacts.

### tc_egress deltas

Symmetric pipeline, plus: Geneve identity option **push** for remote destinations (`bpf_skb_adjust_room`; MTU headroom reserved; encap failure → counter + policy TBD); outbound proxy redirect targets **15001** (vs ingress 15008); for remote destinations `dst_id` is locally unknown (= 0) — enforcement is destination-node-authoritative (recommendation, open ADR).

### Geneve identity option

Option class `MERIDIAN_GENEVE_CLASS`, type `MERIDIAN_OPT_IDENTITY`, length 1 (4-byte body = `__u32 src_identity`, network order). Missing option on tunnel traffic → `src_id = 0` + `GENEVE_DECODE_FAIL` counter (alerts on cross-node identity loss, usually MTU/encap misconfiguration).

### Telemetry emission policy

Ring events at **decision points only**: every deny, the redirect SYN (once per connection by construction), and the first allowed packet of a TCP flow (SYN reused as the free "new flow" detector; UDP is counters-only in v1). Everything else: PERCPU counters. A per-flow LRU "seen" map was rejected — a hot-path map write purely for telemetry.

---

## 2. eBPF map schema (FROZEN v2 — Phase 1 contract freeze, MER-14)

Canonical headers: `bpf/include/meridian_types.h` (structs/enums), `meridian_maps.h` (map defs), `meridian_consts.h` (constants). Go mirrors generated only via bpf2go `-type` (D9). Pin root: `/sys/fs/bpf/meridian/` (tests: `/sys/fs/bpf/meridian-test/<run>/<test>/`), `LIBBPF_PIN_BY_NAME`.

**Byte-order rule:** a field is network order only when copied verbatim from packet bytes (IPs, ports in `flow_event`/`sock_key`/`flow_key`, and `identity_map`'s IP key); it is host order when constructed by BPF or userspace (identity IDs, `policy_key.dst_port` — parsed with `bpf_ntohs`). A mismatch produces silent lookup misses, not errors — the most likely integration bug in the project.

| Map | Type | Key → Value | Entries | Writers → Readers |
|---|---|---|---|---|
| `identity_map` | HASH, NO_PREALLOC | `__u32 pod_ipv4` (BE) → `__u32 identity_id` (host) | 65536 | agent → tc_in, tc_eg, proxy, CLI |
| `policy_map` | HASH, NO_PREALLOC | `policy_key{src_id,dst_id u32; dst_port u16 host; proto u8; direction u8}` → `policy_verdict{action u8; flags u8; _pad u16=0}` (D12/ADR-0003) | 16384 | agent → tc_in, tc_eg, sock_ops (eligibility check), CLI |
| `sockhash` | SOCKHASH (Phase 2) | `sock_key{dst_ip u32 BE; dst_port u16 BE; pad u16=0}` → sock | 65536 | sock_ops → sk_msg |
| `metrics_map` | PERCPU_ARRAY | `metric_id u32` → `u64` | 16 (fixed, reserved slots) | all progs → agent, CLI |
| `flow_events` | RINGBUF | `flow_event` (56 B, layout in header) | 4 MiB (power of 2) | tc_in, tc_eg, sk_msg → agent consumer |
| `denied_flows_map` | LRU_HASH | `flow_key` (16 B, BE) → `deny_info{last_ns u64; count u32; reason u32}` (D14) | 4096 | tc_in, tc_eg → agent, CLI |
| `runtime_config_map` | ARRAY | `0` → `u32` flag bits (bit 0 `FALLOPEN_UNKNOWN`, D16; unset = fail closed) | 1 | agent → tc_in, tc_eg |
| `schema_sentinel_map` | ARRAY | `0` → `enum meridian_schema_version` (= **2**; exported to Go via bpf2go, review D-1) | 1 | agent (stamp/verify) |

v2 deltas from v1 (all in this freeze): `policy_key.pad` → `direction`;
`denied_flows_map` value widened from `u32 drop_reason` to `deny_info`;
`runtime_config_map` added; sentinel value typed as the schema enum. v1 pins
are **refused** (fail closed) — pre-GA upgrade is "wipe the pin dir" (D15);
`sockhash`/`sock_key` remain specified-but-not-instantiated until Phase 2.

Worst-case kernel memory ≈ 17 MB/node (separate from the agent's 50 MB RSS NFR); realistic steady state 4–6 MB, dominated by the 4 MiB ring. `RLIMIT_MEMLOCK`/memcg must permit it; surfaced via `meridian doctor` and `map stats`.

**Update protocol (binding on the agent):**
- Cross-map ordering: identity adds before policies that reference them; policy deletes before identity deletes.
- Snapshot application: diff against applied state; apply adds+modifies, then deletes (D5). Batch syscalls (`BatchUpdate`/`BatchDelete`, kernel ≥ 5.6) are an optimization, not a transaction — phase ordering holds *between* batches.
- All pads zeroed by zero-initializing structs before population.
- Sockmap invariant (CI-enforced): `SOCKMAP_ELIGIBLE` only with `action == ALLOW` and never with `L7_REQUIRED | MTLS_REQUIRED` — a wrongly inserted socket silently bypasses mTLS and L7 policy.

**Versioning:** compatible changes = filling reserved enum slots/flag bits (no bump). Any struct layout, key width, or map add/remove = `MERIDIAN_SCHEMA_VERSION` bump; on mismatch the agent migrates or drains+recreates (re-seeded by the control plane); on a *newer* pinned version it refuses to start.

---

## 3. Node agent internals

Composition root `internal/agent/supervisor`; components are actor-style packages, one loop each, wired by typed channels. Source layout: `cmd/meridian-agent` + `internal/agent/{supervisor, config, bpfobj, attach, linkwatch, xds, datapath, svid, workloadapi, proxyfeed, tproxy, telemetry, identitytable, admin}`, shared contracts in `pkg/wire`.

**Structural invariants (import-direction, enforced by depguard + unexported mutators):**
- `datapath` is the **sole writer** of `identity_map`/`policy_map` and is single-goroutine — single-writer is a compile-time property.
- `bpfobj` is the **sole opener** of pinned objects and owns load-or-reopen (never re-create).
- `config` and `pkg/wire` are leaves; control plane and proxy never import `bpf/` or agent internals.

**Lifecycle FSM:** BOOT (config validate, kernel feature probe — fail closed on missing features) → OPEN_DATAPATH (re-open pins; schema sentinel check) → INTERFACE_RECONCILE (full veth scan **before** subscribing to netlink — closes the missed-event race) → TPROXY_INSTALL → BOOTSTRAP_IDENTITY → XDS_CONNECT → READY. Degraded modes: control-plane unreachable → enforce last-known-good (kernel state is already there; nothing torn down); no bootstrap cert → data path still comes up, control-plane work blocks, critical alert. **Shutdown deliberately leaves** pinned maps, TC filters, cgroup attachments, and TPROXY rules in place so in-flight connections and policy survive restarts (chaos requirement).

**xDS apply pipeline:** RECEIVE → VALIDATE (decode + CC-2 contract checks; failure → NACK, hold last-good) → TRANSLATE (pure `CommitPlan`) → STAGE (referential integrity within the plan) → COMMIT (phases P1 identity-adds → P2 policy-adds → P3 policy-removes → P4 identity-deletes; mid-apply error → per-touched-key rollback from prior-value snapshots, kernel byte-identical to last good, NACK) → **ACK only after commit** (so `meridian_policy_propagation_seconds` measures truth). Receive and apply are decoupled by a latest-wins channel; ADS self-paces because the server won't advance an un-ACKed version.

**SVID manager:** per-workload FSM (KEYGEN → CSR → ISSUING → ACTIVE → ROTATING at 2/3 TTL → SWAP | RETRY across the 8 h window → FAIL_CLOSED near expiry). One hashed timer wheel (not a goroutine per workload). Store is `map[identity]*atomic.Pointer[svidEntry]`; SWAP broadcasts to Workload API watchers — make-before-break, zero dropped proxy connections. Near-expiry serves **no** SVID, never a stale one. Clock is injected (D7).

**Failure matrix (detection → response → signal):** CP disconnect → last-known-good + jittered reconnect → `meridian_xds_connected 0`. NACK → hold last-good → `meridian_xds_nack_total`. Commit error → rollback + NACK → `meridian_datapath_commit_errors_total{phase}`. Netlink ENOBUFS → resubscribe + full reconcile (state, not events, is truth) → `meridian_linkwatch_overflow_total`. Ring overrun → count both ends, never block → `meridian_ringbuf_dropped_events_total`. Proxy down → retry L7 snapshot push, L4 unaffected, alarm on expected-vs-observed redirect divergence. CSR authz-denied → stop retrying, alert (registry bug, not transient).

---

## 4. Integration test environment

**Four tiers** (selected by build tags; same `go test` everywhere):

| Tier | Tag | Needs | Runs |
|---|---|---|---|
| T1 unit | — | any OS | compiler≡reference fuzz, matchers, rotation math, decode/clock helpers |
| T2 bpf | `bpf` | Linux 5.15 + root, **no network** | `bpf_prog_test_run` verdict tests, verifier-clean load |
| T3 netns | `integration` | one kernel + root | multi-"node" netns sim: policy, SOCKMAP, propagation, TPROXY, mTLS e2e |
| T4 e2e/bench | `e2e` | dedicated isolated host | benchmark matrix, chaos suite, K8s demo — nightly only |

**Leak containment:** every resource namespaced per run (`mrdn-<runID>-…` netns, `/sys/fs/bpf/meridian-test/<runID>/<test>/` pins); reaper bookends every suite in `TestMain`; cleanup via `t.Cleanup` registered *before* bring-up. **No sleeps** — all waits are `WaitUntil(deadline, observable-condition)` polls; propagation SLAs are measured (map-presence timestamps), never slept on.

**Multi-node topology (Phase 1+):** per "node" a netns containing the agent, proxy, TPROXY rules, and node-side pod veths; pods are child netns; nodes joined by uplink veths on a host bridge carrying a real Geneve path. TPROXY is netns-scoped, so N simulated nodes run colliding `:15008` listeners safely on one host. Harness-controlled processes enter a netns via `LockOSThread` + `setns` (structured lifecycle control for chaos kills); one-shot workloads use `ip netns exec`.

**CI:** GitHub `ubuntu-22.04` runners (5.15-azure, root via sudo) run T1+T2+T3 on the host kernel; `virtme-ng` nightly for the 5.10/5.15/6.x correctness matrix (never for perf numbers); T4 on a self-hosted pinned-CPU host with warmup + ≥10 runs + coefficient-of-variation reporting (CV > 5 % → rerun, not averaged). PR gate = T1 + T2 + fast T3 subset (allow/deny, SOCKMAP-negative, <500 ms propagation — the three highest-impact regressions).

**Chaos mechanics:** agent SIGKILL mid-stream (assert bytes keep flowing, pins intact, restart re-opens); control-plane partition via netns iptables DROP (detection path) and SIGSTOP (unresponsive-but-connected path) — last-known-good held, no transient widening, convergence after heal; cert-expiry-during-partition via fake clock — rotation retries, near-expiry fails closed, 8 h window absorbs the outage.

**PKI fixtures:** ephemeral root + P-384 intermediate per run (real curve/depth); `go-spiffe` fake workload clients for Workload API and "valid-but-unauthorized SVID still rejected" tests.

---

## 5. Build pipeline

- `make ebpf` → `go generate ./bpf/...` → bpf2go (`-target bpfel`, `-type` per cross-boundary struct, pinned clang via `$CLANG`); output (`*_bpfel.go`/`.o`) **committed**.
- Flags: `-O2` (verifier-mandatory), `-g` (BTF for CO-RE), `-mcpu=v3` (5.15-safe, verifier-friendlier), `-Wall -Werror`, `-Iinclude` (relative — no absolute paths leak into objects).
- `vmlinux.h` committed; CI regenerates from the runner kernel, builds, restores the committed copy before diffing bindings (CO-RE relocations make bindings independent of which 5.15.x produced the header).
- `make verify-gen` is the determinism gate: regenerate, `git diff --exit-code`.
- Test entry points: `make test-unit | test-bpf | test-integration | bench | test-clean | doctor`.

## 6. Package dependency rules

```text
cmd/* ──► internal/{agent,control,proxy} ──► pkg/wire (leaf: stdlib only)
                      │
                      └──► bpf/ (leaf: cilium/ebpf + stdlib; generated mirrors)
```

1. `pkg/wire`: stdlib only — the shared vocabulary of control plane, agent, proxy.
2. `internal/agent/config`: imports nothing internal (leaf within the agent).
3. `internal/agent/datapath`: sole `identity_map`/`policy_map` writer.
4. `internal/agent/bpfobj`: sole pinned-object opener (load-or-reopen lives in one place).
5. `internal/control`, `internal/proxy`: never import `bpf/` or `internal/agent`.
6. `internal/reference` (policy oracle): `pkg/wire` + stdlib only — must stay obviously correct.

Enforced by depguard rules in `.golangci.yml`; the single-writer rules additionally by keeping mutation helpers unexported outside their owning packages.
