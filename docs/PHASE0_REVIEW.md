# Phase 0 Implementation Review

Reviewed: all Phase 0 code and the P0-002 stub batch, as of this tree (no commits yet).
Reviewers' hats: principal eBPF engineer + infrastructure architect.
Scope: architecture consistency, verifier risk, Phase 1 compatibility, test coverage, missing abstractions.

**Verdict: NOT READY for Phase 1.** See [§6](#6-readiness-decision). Two code defects
(one compile-breaking) show the P0-002 batch was never compiled, and none of the
Linux verification gates (MER-1..MER-10) have run.

---

## 1. Architecture consistency

**Consistent and good:**

- The frozen contract chain holds: `meridian_types.h` (56-byte `flow_event` +
  `_Static_assert`) → bpf2go mirror → `telemetry.fromWire` → domain `Event`.
  Wire vs domain separation in `internal/agent/telemetry/event.go` is exactly
  right and well documented.
- `bpfobj` as the sole pin opener, schema sentinel fail-closed, re-open-never-recreate:
  matches D6 and the restart contract.
- `pkg/wire` leaf discipline is real (stdlib only) and depguard-enforced; the
  four `.golangci.yml` walls match the package dependency rules in ARCHITECTURE.md.
- Test harness honors all four binding design rules (per-run namespacing, reaper,
  `t.Cleanup`, no sleeps).

**Inconsistencies found:**

| # | Issue | Where |
|---|-------|-------|
| C-1 | **Agent binary lost TC attach.** `cmd/meridian-agent/main.go` only loads + tails the ring; its own docstring says "optional tc attach", README line 43 documents `sudo ./bin/meridian-agent --iface <veth>`, and MER-9's acceptance criteria require `--iface`. The `attach.Manager` interface exists with no implementation. As written, the Phase 0 smoke test (MER-9) is impossible: only the *test harness* can attach the program, the product cannot. | `cmd/meridian-agent/main.go`, `README.md:43`, `internal/agent/attach/doc.go` |
| C-2 | **P0-002 stubs contradict the recorded deferral decision.** `PHASE0_CHECKLIST.md` ("Deliberately deferred") states `internal/agent/{datapath,attach,linkwatch,xds,svid,...}`, `internal/control/`, `internal/proxy/`, `internal/reference/` are "created by the phase that first needs them". They now all exist as interface stubs. Either the checklist/ARCHITECTURE must be updated to record interface-first scaffolding as the new plan, or the stubs should go. Interface-first also carries design risk: contracts like `xds.Client` were defined with no implementation pressure-testing them. | `PHASE0_CHECKLIST.md:57`, 14 stub packages |
| C-3 | **`pkg/wire` is a third representation of datapath types.** CC-6/D9 say cross-boundary structs are single-sourced in C with bpf2go mirrors. `wire.PolicyRuleKey`/`PolicyVerdict`/`PolicyFlags` now pre-state the same contract in Go before `policy_key`/`policy_verdict` exist in C. Acceptable for the control-plane side **only if** `datapath.Writer` is the sole wire→bpf2go translator and an equivalence test pins the bit/field mapping (see T-gaps). This boundary rule is not yet written down anywhere. | `pkg/wire/policy_snapshot.go`, `docs/ARCHITECTURE.md` D4/D9 |
| C-4 | **Duplicate netns tooling.** `test/harness/netns.go` (Go, `tc qdisc add`) and `scripts/netns/*.sh` (bash, `tc qdisc replace`) implement the same fixture with already-divergent commands. `docs/NETNS_SCRIPTS.md` frames the scripts as operator/debug aids, which is fine — but nothing prevents drift. Decide: harness shells out to the scripts, or the scripts carry a "debug-only, harness is authoritative" banner. | `test/harness/netns.go:78`, `scripts/netns/create_veth_pair.sh` |
| C-5 | Stale statements: `Makefile` build target comment says "control/CLI binaries arrive in Phases 3/6" but `cmd/meridian-control` and `cmd/meridian` stubs now exist; agent `main.go` docstring mentions attach it doesn't do. | `Makefile:89`, `cmd/meridian-agent/main.go:6` |

## 2. Verifier concerns (`bpf/counter.c`)

**Assessment: low risk.** The program follows the canonical verifier-safe shape:

- Every packet access is preceded by an explicit `data_end` check
  (`eth + 1`, `ip + 1`, `l4 + L4_PORTS_BYTES`).
- The variable L4 offset is derived from `ihl` **after** clamping to 5..15
  (`counter.c:60-63`), so the verifier sees a bounded scalar before
  `(void *)ip + ip_hdr_bytes` — this is the pattern 5.15 provably accepts.
- No loops, trivial stack usage, event fields written directly into
  `bpf_ringbuf_reserve`d memory (no 56-byte stack copy).
- `bpf_ringbuf_reserve` (5.8+) and `-mcpu=v3` (5.1+) are safe on the 5.15 target;
  reserve-failure is counted, never blocks (`TC_ACT_OK` unconditionally).

Residual risks to watch at MER-6, none requiring code change now:

- **V-1**: `ip->ihl` is a bitfield read through BTF-generated `vmlinux.h`; correct
  for `-target bpfel` on x86-64/arm64, but the first `make ebpf` should confirm
  clang 17 doesn't legalize it into a wider read that trips the `ip + 1` bound
  (it shouldn't — both bitfields live in byte 0).
- **V-2**: VLAN-tagged frames (`h_proto` = 802.1Q) fall into the non-IPv4
  passthrough, so they're counted but never parsed. Fine for Phase 0 veths;
  must be revisited when Phase 1 attaches to real pod links.
- **V-3**: `_license` is `GPL` — required for `bpf_ringbuf_*`; keep it in mind
  for the MER-13 license split (the `bpf/` tree must stay GPL-2.0).

## 3. Phase 1 compatibility

**Forward-compatible by construction:** frozen event layout with explicit pads,
reserved metric slots 2..15 (no map resize ⇒ no pin invalidation), schema
sentinel for layout bumps, `gen.go` one-line-per-program pattern with the Phase 1
directive already drafted, pinned-maps restart contract.

**Gaps that will bite Phase 1 if not addressed:**

- **P-1**: `wire.PolicyRuleKey` has **no direction field** (ingress vs egress) and
  no port-wildcard concept. The PRD's policy model and the TC architecture
  (separate ingress/egress hooks) almost certainly need direction in the key.
  Changing the key type later ripples through `control.Store`, `Compiler`,
  `datapath.Writer`, and `reference.Evaluator`. Decide before any Phase 1 code
  consumes it — fold into the MER-11/12 ADR round.
- **P-2**: `schemaVersion` in `loader_linux.go:19` hand-mirrors
  `MERIDIAN_SCHEMA_VERSION`; the C macro itself is never read by any program, so
  Go is silently the authoritative copy. Drift is caught only by humans. Phase 1
  fix: expose it via bpf2go (e.g. an `enum meridian_schema { ... }` listed in
  `-type`) or a `.rodata` volatile const, and delete the Go literal.
- **P-3**: Program **re-pin will EEXIST on agent restart**. `LoadCounter` re-opens
  maps idempotently, but `Pin(progPin)` (as the integration test and any attach
  implementation do) fails if the pin already exists. The attach implementation
  (F-3) must unpin-or-replace; MER-9's restart test will catch this only if the
  test restarts with the program pinned.
- **P-4**: ADR tickets MER-11 (unknown-identity posture) and MER-12 (Geneve
  placement) are unwritten; `docs/adr/` doesn't exist. These freeze contracts
  Phase 1 depends on — already gating per the ticket plan, reaffirmed here.

## 4. Test coverage

**Strong:** tier structure (T1 portable / T2 `bpf` / T3 `integration`), harness
discipline, T3 exercising the *real* consumer end-to-end, dry-run script tests,
clock/byte-order helpers unit-tested.

**Gaps (ordered by risk):**

- **T-1**: `pkg/wire` has zero tests — and contains a compile error (F-1). Even a
  trivial flags test (`PolicyFlagL7Required == 1<<1`) would have caught it and
  permanently pins the D4 bit contract.
- **T-2**: The **fail-closed path of `checkOrStampSchema` is untested.** It is the
  one safety property the loader exists to provide. Five-line T2 test: load,
  `Put` sentinel = 99, reload from the same pinDir, require error.
- **T-3**: No negative T2 cases: truncated Ethernet frame, `ihl < 5`, non-IPv4
  ethertype — each should return `TC_ACT_OK`, bump `METRIC_PACKETS_TOTAL`, and
  (for the malformed ones) emit no event / zero ports. `prog_test_run` makes
  these nearly free, and they are the regression net for every future parser edit.
- **T-4**: No T2 assertion on the **ring record bytes** (read one event after
  `prog.Run`, assert field values incl. zeroed pads). Today layout drift is
  caught only at T3, with worse diagnostics.
- **T-5**: `Consumer` decode-error and shutdown paths untested; `Stats()` has no
  consumer.
- **T-6**: `sumPercpu` + `metricPacketsTotal` duplicated across
  `test/bpf/progrun_test.go` and `test/integration/counter_test.go` (DRY violation
  already real — see A-2).
- **T-7**: `example_producer_test.go` has a failing expectation (F-2) — proof the
  T1 suite has never been run (Go is absent on the dev host; MER-5 covers this).

## 5. Missing abstractions

- **A-1**: **TC attach implementation** — the interface exists (`attach.Manager`),
  the harness has working mechanics, the product has neither. Biggest functional
  hole in Phase 0 (same finding as C-1/F-3).
- **A-2**: **Metrics reader.** Per-CPU summing belongs in a real package (e.g.
  `internal/agent/telemetry` or `bpfobj`) — Phase 1's Prometheus exporter needs
  it anyway, and it de-duplicates T-6.
- **A-3**: **Generated metric/verdict constants.** Add `-type metric_id`
  (and `-type flow_verdict`) to the bpf2go directive so Go code and tests use
  generated constants instead of hand-mirrored literals
  (`metricPacketsTotal = uint32(0)` ×2, `telemetry.Verdict` values).
- **A-4** (minor): `Consumer` has no `Close()`; if `New` succeeds but `Run` is
  never called, the ringbuf reader fd leaks.
- Deliberately *not* missing: logging/DI frameworks, event-sink interfaces —
  the bare `Handler` func is the right Phase 0 size (YAGNI).

---

## Required fixes (before anything else lands)

| # | Sev | Fix | Files |
|---|-----|-----|-------|
| F-1 | **CRITICAL — does not compile** | `PolicyFlags` const block has no init expression (`const ( PolicyFlagSockmapEligible ... )` is invalid Go). Every package importing `pkg/wire` (10+) fails to build. Fix to match D4 exactly: `PolicyFlagSockmapEligible PolicyFlags = 1 << iota` then `PolicyFlagL7Required`, `PolicyFlagMTLSRequired`, `PolicyFlagAudit` (bits 0–3; 4–7 reserved = 0). Add the T-1 pin test in the same change. | `pkg/wire/policy_snapshot.go:62-67` |
| F-2 | **HIGH — failing test** | `TestExampleProducerEventFor` expects `MonotonicNs == 1_700_000_000` but `baseMono(1_000_000) + 7 × 100ms = 701_000_000`. Author intended `baseMono = 1_000_000_000`. Fix the fixture (the producer math is correct). | `internal/agent/telemetry/example_producer_test.go:15,22` |
| F-3 | **HIGH** | Restore agent TC attach: either reinstate `--iface` + pin-and-`tc`-attach in `main.go` (Phase 0 mechanism, same as the harness) or land a minimal `attach.Manager` implementation the binary uses. Must unpin-or-replace the program pin (P-3). Fix the stale docstring and keep README/MER-9 truthful. | `cmd/meridian-agent/main.go`, `internal/agent/attach/` |
| F-4 | **HIGH — process** | Execute the Linux verification chain (MER-1 → MER-10). Nothing kernel-facing has ever run: no `go.sum`, no `vmlinux.h`, no generated bindings, zero git commits (`verify-gen` needs a commit to diff against). Phase 0 is *written*, not *done*. | per PHASE0_TICKETS.md |
| F-5 | MEDIUM | Reconcile P0-002 stubs with the recorded deferral decision (C-2): update `PHASE0_CHECKLIST.md` + ARCHITECTURE to bless interface-first scaffolding, or delete the stubs. | `PHASE0_CHECKLIST.md`, `docs/ARCHITECTURE.md` |
| F-6 | LOW | `consumer_linux.go` import block isn't gofmt-sorted (`"errors"` before `"context"`) — will churn the first time anyone formats. | `internal/agent/telemetry/consumer_linux.go:6-7` |

## Technical debt register

| # | Debt | Pay-down trigger |
|---|------|------------------|
| D-1 | `schemaVersion` Go literal mirrors C macro by hand (P-2) | Phase 1 schema freeze — generate it |
| D-2 | wire↔C policy type equivalence has no test and no written boundary rule (C-3) | When `policy_verdict` lands in C: equivalence test + `datapath.Writer` sole-translator rule in ARCHITECTURE.md |
| D-3 | `sumPercpu`/metric-id literals duplicated in tests (T-6, A-3) | With A-2 metrics reader, or first Prometheus work |
| D-4 | Dual netns tooling (Go harness + bash scripts) already command-divergent (C-4) | Before Phase 1 grows the fixture (multi-node) |
| D-5 | `PolicyRuleKey` lacks direction/wildcards (P-1) | MER-11/12 ADR round — decide before any consumer code |
| D-6 | Program pin EEXIST on restart (P-3) | F-3 attach implementation |
| D-7 | CI `golangci-lint-action` pinned to `version: latest` — non-reproducible lint in an otherwise determinism-obsessed pipeline | Next CI touch (MER-10) |
| D-8 | `Consumer` lacks `Close()` for the not-Run path (A-4) | When the supervisor owns component lifecycles |
| D-9 | Stamp-time race in sentinel: crash between map create and stamp leaves version 0; a *newer* build could later stamp over old-build maps. Benign now (schema 1 only), unsound at schema 2+ | Schema version 2 — make stamping part of an atomic init marker |
| D-10 | VLAN frames bypass the parser (V-2) | Phase 1 real-link attach |

## 6. Readiness decision

**NOT READY for Phase 1.** Hard blockers, in order:

1. **The tree does not compile** (F-1) and a unit test is wrong (F-2) — the P0-002
   batch was demonstrably never built or tested, which also means the repo's own
   TDD/coverage standards were skipped for that batch.
2. **Zero verification gates have run** (F-4): all four Phase 0 exit criteria
   (deterministic `make ebpf`, verifier-clean load, byte-correct ring decode,
   counter readback) remain unproven; there is not even an initial git commit.
3. **The agent cannot attach its own program** (F-3) — the headline Phase 0
   deliverable ("counter program loads and attaches") is only achievable via
   test scaffolding.
4. **Contract-freezing ADRs are open** (P-4, D-5): unknown-identity posture,
   Geneve placement, plus module path / license / bpf2go prefix (MER-13).

**Re-evaluation criteria:** F-1..F-3 fixed with the T-1/T-2 tests added →
MER-1..MER-7 green in the VM → MER-8 + MER-10 green in CI → MER-11/12/13 closed.
At that point Phase 0 meets its own exit definition and Phase 1 can start.

The architecture itself is **sound** — contracts, layering, harness discipline,
and verifier strategy are all Phase-1-grade. The gap is entirely execution and
verification, not design.
