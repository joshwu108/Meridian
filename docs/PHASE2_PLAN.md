# Phase 2 Work Breakdown — SOCKMAP Redirect + ADS Conformance

Scope (ROADMAP week 4): gated `sock_ops` + `sk_msg` intra-node redirect (eBPF
P2.1–P2.2), control-plane ADS server vs in-memory agent stub + CP-3 conformance
suite. Exit: **denied flow never SOCKMAP-redirected; REST policy change visible
in stub < 500 ms** (PRD success criterion #4, measured).

Carry-in from Phase 1: frozen v2 map schemas (MER-14/34), `POLICY_FLAG_SOCKMAP_ELIGIBLE`
in `policy_verdict.flags` (ARCHITECTURE D4), reference evaluator + compiler
sockmap invariant (MER-22/23), agent stub + two-node harness (MER-27/28).

Owner roles (one person can hold several; see staffing mappings at the end):

| Role | Profile |
|---|---|
| **eBPF** | Kernel/C: cgroup `sock_ops`, SOCKHASH `sk_msg`, verifier discipline |
| **Agent** | Go systems: cgroup attach, sockhash pin re-open, loader extensions |
| **Platform** | Pure-Go: memory store, identity registry, REST, ADS state machine |

---

## 0. Phase-2 entry gate (hard sequencing rule)

**No Phase-2 implementation ticket may merge until MER-34 (Phase-1 exit) is
green.** This mirrors the Phase-0→Phase-1 rule (Phase 0 exit + MER-11/12/13
before Phase-1 code).

Phase-2 **planning** (this document, [PHASE2_TICKETS.md](PHASE2_TICKETS.md),
[PHASE2_GATES.md](PHASE2_GATES.md)) has no dependency and may land while
Phase-1 gates are still open — but implementation work on MER-47+ stays
blocked until:

1. All six Phase-1 gates in [PHASE1_GATES.md](PHASE1_GATES.md) are armed and
   green (P1.1, P1.2, P1.3, CP-2, O-2, EXIT).
2. ADR-0004 map-schema freeze is published (MER-34).
3. `docs/PHASE0_REVIEW.md` carries a "Phase 2 entry APPROVED" addendum (owned
   by MER-35; the entry gate references MER-34 green, not MER-35 alone).

Recorded in [ROADMAP.md](../ROADMAP.md) week-4 row and
[PHASE2_GATES.md](PHASE2_GATES.md).

---

## 1. Architecture updates (land via MER-47 and MER-59)

Deltas to `docs/ARCHITECTURE.md`; D18–D20 append to the decision log.

- **D18 — `sockhash` map instantiated.** Phase 1 froze `sock_key` and the map
  schema but left `sockhash` specified-but-not-instantiated (ARCHITECTURE §2).
  Phase 2 adds the pinned `BPF_MAP_TYPE_SOCKHASH` map to `meridian_maps.h` and
  bpf2go; all programs that reference it share the same pin.
- **D19 — Cgroup `sock_ops` attach point.** `sock_ops` attaches to the node's
  unified cgroup v2 hierarchy (`/sys/fs/cgroup` or a dedicated Meridian cgroup
  subtree). The agent owns attach/detach; tests use a harness-created cgroup.
  Programs: `BPF_CGROUP_SOCK_OPS` on the cgroup fd.
- **D20 — `sk_msg` attach via SOCKHASH verdict.** `sk_msg` attaches with
  `BPF_SK_MSG_VERDICT` to the **sockhash map fd** (not a cgroup). The agent
  loads both programs from a single bpf2go collection object alongside TC
  programs; pin re-open path matches `bpfobj` Phase-1 semantics.
- **CC-5 sockmap invariant (permanent negative test).** SOCKMAP eligibility is
  a **policy verdict flag**, not a performance toggle. `sock_ops` may call
  `bpf_sock_hash_update()` only when the flow's compiled verdict has
  `POLICY_FLAG_SOCKMAP_ELIGIBLE` set (which requires `action == ALLOW` and
  `¬L7_REQUIRED ∧ ¬MTLS_REQUIRED` — enforced at compile time in MER-22/23).
  Absent the flag, **no SOCKHASH insertion**. CI carries a permanent negative
  test: DENY, L7-required, mTLS-required, and REDIRECT flows must never appear
  in the SOCKHASH (gate P2.1-N).

Package graph changes: `bpf/sock_ops.c`, `bpf/sk_msg.c` (new); `internal/control/`
gains `store/`, `ads/`, `rest/`; `internal/agent/attach` gains cgroup helpers;
`cmd/meridian-control` graduates from stub to a runnable dev server.

## 2. Implementation tickets

All tickets ≤ 4h. ∥ Wave = tickets in the same wave run concurrently;
different lanes never block each other except where Deps say so.

| ID | Ticket | Owner | Est | Dependencies | Files touched | Wave |
|----|--------|-------|-----|--------------|---------------|------|
| MER-47 | **Phase 2 contract land**: instantiate `sockhash` in `meridian_maps.h`; `sock_ops.c`/`sk_msg.c` skeletons in `gen.go`; bpf2go `-type` for `sock_key`; shared helpers header | eBPF + Agent (pair) | 2–3h | **Phase-2 entry** (MER-34 green) | `bpf/include/meridian_maps.h`, `bpf/sock_ops.c` (new), `bpf/sk_msg.c` (new), `bpf/gen.go`, generated bindings | **0** |
| MER-48 | **`sock_ops.c`: gated SOCKHASH population (P2.1 core)** | eBPF | 3–4h | MER-47 | `bpf/sock_ops.c`, `bpf/include/meridian_helpers.h` (new, shared policy lookup) | 1 |
| MER-49 | **P2.1-N GATE — permanent SOCKMAP-negative test** | eBPF + Platform (pair) | 3–4h | MER-48, MER-22 | `test/bpf/sockmap_negative_test.go` (new), `test/gates/manifest.txt` | 2 |
| MER-50 | **`sk_msg.c`: redirect + fall-through + `latency_ns`** | eBPF | 3–4h | MER-48 | `bpf/sk_msg.c`, `bpf/include/meridian_consts.h` (metric slot for redirect) | 2 |
| MER-51 | **P2.2 GATE — byte integrity + denied never redirected** | eBPF + Agent (pair) | 4h | MER-50, MER-57 | `test/integration/sockmap_integrity_test.go` (new) | 4 |
| MER-52 | **P2.2-BENCH — intra-node latency measurement** | eBPF | 2–3h | MER-51 | `test/integration/sockmap_bench_test.go` (new, `e2e` tag) | 5 |
| MER-53 | **CP-1 slice: memory store + identity registry + REST skeleton** | Platform | 4h | **Phase-2 entry** | `internal/control/store/memory.go` (new), `identity/registry.go` (new), `rest/server.go` (new), `cmd/meridian-control/main.go` | 1 |
| MER-54 | **ADS server: version/nonce state machine + ordered push** | Platform | 4h | MER-53 | `internal/control/ads/server.go` (new), `ads/versioning.go` (new), `go.mod` | 2 |
| MER-55 | **ADS agent stub (in-memory xDS client)** | Platform | 3–4h | MER-54 | `internal/control/ads/stub_agent.go` (new), `ads/stub_agent_test.go` (new) | 3 |
| MER-56 | **CP-3 GATE — ADS conformance + <500 ms propagation** | Platform | 4h | MER-55 | `internal/control/ads/conformance_test.go` (new), `test/gates/manifest.txt` | 4 |
| MER-57 | **Agent cgroup + SOCKHASH attach path** | Agent | 3–4h | MER-47 | `internal/agent/attach/cgroup_linux.go` (new), `attach/sockmap_linux.go` (new), `cmd/meridian-agent/main.go` | 2 |
| MER-58 | **`bpfobj` loader: sock_ops/sk_msg + sockhash re-open** | Agent | 2–3h | MER-47, MER-57 | `internal/agent/bpfobj/loader_linux.go`, `loader_test.go` | 3 |
| MER-59 | **EXIT GATE — Phase-2 doc reconciliation + Phase-3 entry** | eBPF + all (review) | 2h | MER-49, MER-51, MER-56, MER-52 | `docs/PHASE2_GATES.md`, `README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md` | 6 |

**Total ≈ 40–46h.** Gates: P2.1-N = MER-49 · P2.2 = MER-51 · P2.2-BENCH =
MER-52 · CP-3 = MER-56 · **Phase 2 exit / Phase 3 entry** = MER-59.

## 3. Parallelization plan

**Serialization points:** Phase-2 entry (MER-34 green) blocks all implementation;
**MER-47** is the first code ticket (instantiates sockhash + bpf2go wiring).

```text
[ENTRY]  MER-34 green (Phase-1 exit) — no MER-47+ merges before this

Wave 0  ──  MER-47 (eBPF+Agent pair: sockhash land + skeletons)        [½ day]

Wave 1  ──  eBPF: MER-48        Platform: MER-53
            Agent: (prep MER-57 deps only)                              [day 1]

Wave 2  ──  eBPF: MER-49 (P2.1-N ✓) ∥ MER-50
            Agent: MER-57        Platform: MER-54                       [day 2]

Wave 3  ──  Platform: MER-55     Agent: MER-58                          [day 3]

Wave 4  ──  eBPF+Agent: MER-51 (P2.2 ✓)    Platform: MER-56 (CP-3 ✓)   [day 4–5]

Wave 5  ──  eBPF: MER-52 (bench, nightly T4)                            [day 5]
Wave 6  ──  All: MER-59 (Phase-2 exit ✓ → Phase 3 entry)              [day 5–6]
```

**Critical path** (≈ 18–22h): MER-47 → MER-48 → MER-50 → MER-51 → MER-59.
The control-plane chain (53→54→55→56) runs fully parallel until Wave 4, where
CP-3 and P2.2 gates converge at MER-59.

**Staffing mappings:**

- **3 people** (eBPF / Agent / Platform): the wave diagram as drawn; ~5–6
  working days on the 5.15 target.
- **2 people** (ROADMAP workstreams A/B): A takes eBPF+Agent
  (47→48→50→57→58→51→52), B takes Platform (53→54→55→56). ~1.5 weeks.
- **1 person**: critical path + interleave Platform after MER-50; defer
  MER-52 (bench) to nightly. ~2 weeks.

**Rules that keep the parallelism safe:**

1. Nobody edits `sockhash` schema or `sock_key` layout after MER-47 without an
   explicit schema bump (ADR + MER-34-style re-freeze).
2. `sock_ops` is the **only** writer to `sockhash`; `sk_msg` is read-only on
   the map. Agent never writes socket entries — only attaches programs.
3. The P2.1-N negative test (MER-49) lands **before** any sk_msg redirect test
   that could mask a policy bypass — same ordering discipline as Phase 1's
   verdict matrix before live integration.
4. ADS conformance (MER-56) runs against the **in-memory stub**, not the real
   agent (A-3 is Phase 3). Propagation SLA is stub receive time, not kernel
   map write time.
5. Every lane lands tests in the same PR as its code; gate stubs start
   `armed=no` in `test/gates/manifest.txt` until upstream tickets merge.
