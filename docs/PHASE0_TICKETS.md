# Phase 0 Implementation Tickets

Derived from [PHASE0_CHECKLIST.md](../PHASE0_CHECKLIST.md). Scaffolding (headers, counter.c, loader, consumer, harness, tests, Makefile, CI) is already committed; these tickets take the repo from "written" to "verified green" plus the decisions that gate Phase 1.

Estimates assume one engineer; every ticket ≤ 4h. **∥ Lane** marks tickets that can be worked concurrently: tickets in different lanes (or marked "any") never block each other; within a lane, order follows the Deps column.

| ID | Ticket | Est | Acceptance criteria | Deps | Files expected to change | ∥ Lane |
|----|--------|-----|---------------------|------|--------------------------|--------|
| MER-1 | **Dev VM bring-up & environment validation** | 1–2h | `limactl start --name=meridian test/vm/meridian.yaml` boots and provisions without manual fixes; `limactl shell meridian -- make doctor` reports all kernel configs `ok`, clang ≥ 15, Go ≥ 1.22, bpftool present; bpffs mounted | — | `test/vm/meridian.yaml`, `test/vm/provision.sh` (bug fixes only) | A (start) |
| MER-2 | **Resolve Go module graph** | 0.5h | `go mod tidy` succeeds in the VM; `go.sum` committed; `cilium/ebpf v0.17.x` + `golang.org/x/sys` pinned; second `tidy` run is a no-op | MER-1 | `go.mod`, `go.sum` | A |
| MER-3 | **Generate vmlinux.h + first bpf2go run** | 1–2h | `make vmlinux` writes `bpf/include/vmlinux.h`; `make ebpf` compiles `counter.c` clean under `-Wall -Werror` and emits `counter_bpfel.go` + `counter_bpfel.o`; both committed | MER-1 | `bpf/include/vmlinux.h` (new), `bpf/counter_bpfel.go` (new), `bpf/counter_bpfel.o` (new), possibly `bpf/counter.c`, `bpf/gen.go`, `Makefile` | A (∥ MER-2) |
| MER-4 | **Align generated identifiers; full Linux compile** | 1–2h | Generated names verified against code assumptions (`CounterObjects{MeridianCounter, FlowEvents, MetricsMap, SchemaSentinelMap}`, `CounterFlowEvent` fields); `go build ./...` green in VM; `make build` produces `bin/meridian-agent` | MER-2, MER-3 | `internal/agent/telemetry/consumer_linux.go`, `internal/agent/bpfobj/loader_linux.go`, `test/bpf/progrun_test.go`, `test/integration/counter_test.go`, `cmd/meridian-agent/main.go` | A |
| MER-5 | **T1 unit tests green (Linux + macOS)** | 1h | `make test-unit` passes in the VM; Go installed on the macOS host (`brew install go`) and `go test ./...` passes there too (portable packages must build with linux files excluded); `gofmt`/`go vet` clean | MER-2 (mac half: none) | `internal/agent/telemetry/event.go`, `event_test.go`, `test/harness/*.go` (portability fixes only) | B (∥ MER-3/4) |
| MER-6 | **T2 green: verifier-clean load + prog_test_run** | 2–4h | `make test-bpf` passes: program loads with zero verifier errors on 5.15, synthetic packet returns `TC_ACT_OK`, PERCPU counter reads exactly 1; on any verifier rejection, the log is captured and the fix commented in `counter.c` | MER-4 | `bpf/counter.c` (+ regenerated bindings), `test/bpf/progrun_test.go`, `internal/agent/bpfobj/loader_linux.go` | A |
| MER-7 | **T3 green: netns integration end-to-end** | 2–4h | `make test-integration` passes: counter ≥ ping count AND the real telemetry consumer decodes a peer→host event with correct IPs/timestamp; after a deliberately failed run, `ip netns list` shows no `mrdn-*` and `/sys/fs/bpf/meridian-test` is empty (reaper verified) | MER-6 | `test/harness/harness.go`, `test/harness/netns.go`, `test/integration/counter_test.go` | A |
| MER-8 | **Codegen determinism gate** | 1–2h | `make verify-gen` run twice back-to-back produces zero diff; no absolute paths embedded in `.o` (checked with `strings`); clang pin documented; vmlinux.h restore flow validated locally | MER-3 | `Makefile`, `bpf/gen.go`, `.github/workflows/ci.yml` | C (∥ MER-4–7) |
| MER-9 | **Agent binary smoke test + restart contract** | 1–2h | `sudo bin/meridian-agent --iface <veth>` prints decoded events for live pings; Ctrl-C detaches cleanly; restarting the agent against the same `--pin-dir` re-opens pinned maps (schema sentinel accepted, counters continue, no wipe) | MER-7 | `cmd/meridian-agent/main.go`, `internal/agent/bpfobj/loader_linux.go` | A |
| MER-10 | **CI pipeline green** | 1–3h | All three workflow jobs pass on a PR: lint+unit, verify-gen, bpf+integration; runner package names / kernel quirks fixed; `make test-clean` step reaps leftovers on failure paths | MER-5, MER-6, MER-7, MER-8 | `.github/workflows/ci.yml`, `Makefile`, `.golangci.yml` | A (final) |
| MER-11 | **ADR-0001: unknown-identity posture (CC-5)** | 1–2h | `docs/adr/0001-unknown-identity-posture.md` records the decision (fail-open passthrough vs default-deny-on-attach), consequences, and the Phase 1 plan for the `FALLOPEN_UNKNOWN` toggle + attach-ordering implications | — | `docs/adr/0001-unknown-identity-posture.md` (new), `docs/ARCHITECTURE.md` (decision log update) | any |
| MER-12 | **ADR-0002: Geneve parse placement spike + decision** | 3–4h | Small spike (two netns + Geneve link in the VM) answers whether the kernel's decap strips options before an inner-device TC hook; `docs/adr/0002-geneve-parse-placement.md` records the chosen attach point (underlay pre-decap vs tunnel-device program) and agent attach-topology implications | MER-1 (VM for spike) | `docs/adr/0002-geneve-parse-placement.md` (new), `docs/ARCHITECTURE.md` | B |
| MER-13 | **Project decisions: module path, license, bpf2go prefix** | 1–3h | Module path confirmed or renamed tree-wide (placeholder is `github.com/joshuawu/meridian`; renaming later is tree-wide — must close before Phase 1 code); `LICENSE` added (bpf/ = GPL-2.0 required; Go license chosen); bpf2go prefix convention (per-program vs combined collection at Phase 1) recorded in `bpf/gen.go` | — (before any Phase 1 ticket) | `go.mod` (+ all imports if renamed), `LICENSE` (new), `bpf/gen.go`, `PHASE0_CHECKLIST.md` | any |

## Dependency graph / suggested schedule

```text
Lane A (critical path): MER-1 → {MER-2 ∥ MER-3} → MER-4 → MER-6 → MER-7 → MER-9 → MER-10
Lane B (parallel):      MER-5 (after MER-2) · MER-12 (after MER-1)
Lane C (parallel):      MER-8 (after MER-3)
Anytime:                MER-11 · MER-13
```

- **Critical path ≈ 9–17h** (MER-1→2/3→4→6→7→9→10); MER-6 and MER-7 carry the schedule risk (verifier debugging, netns/tc quirks).
- With two people: one drives Lane A; the other clears MER-5/8/11/12/13 — everything off the critical path is done before MER-7 finishes.
- **Phase 0 exit** = MER-7 + MER-8 + MER-10 green (covers all four ROADMAP week-1 gates: deterministic `make ebpf`, verifier-clean load, byte-correct ring decode, counter readback).
- **Phase 1 entry** additionally requires MER-11, MER-12, MER-13 closed (they freeze contracts Phase 1 code depends on).
