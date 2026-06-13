# Meridian

Meridian is an eBPF-native service mesh data plane. It replaces iptables-based
sidecar proxies with kernel-resident eBPF programs that intercept container
traffic, enforce SPIFFE/mTLS identity and L7 policy, and export per-request
telemetry — at kernel speed with near-zero overhead. A lightweight
xDS-compatible control plane pushes configuration to per-node agents over gRPC.

## Status

**Phase 0 — complete (MER-35 sign-off).** Phase 1 work is underway; see
[PHASE0_REVIEW.md](docs/PHASE0_REVIEW.md) and [PHASE0_GATE_EVIDENCE.log](docs/PHASE0_GATE_EVIDENCE.log).

## Prerequisites

Meridian's data plane runs on **Linux ≥ 5.10** (development and CI target:
**Ubuntu 22.04 LTS / kernel 5.15**) with BTF, TC BPF, ring buffer, and SOCKHASH
support (PRD §6).

- **Linux:** clang/LLVM ≥ 15 (BPF target), `libbpf-dev`, `bpftool`, Go 1.22+.
- **macOS:** eBPF cannot run natively — use the bundled Lima VM:

  ```bash
  limactl start --name=meridian test/vm/meridian.yaml
  limactl shell meridian
  ```

## Quickstart

```bash
make doctor            # check kernel features + tool versions
make vmlinux           # generate bpf/include/vmlinux.h from kernel BTF (once per kernel)
make ebpf              # clang compiles bpf/*.c, bpf2go regenerates committed Go bindings
make build             # build bin/meridian-agent
make test-unit         # T1: pure-Go tests (runs anywhere, incl. macOS)
make test-bpf          # T2: bpf_prog_test_run suites (root, Linux)
make test-integration  # T3: live netns end-to-end (root, Linux)
```

Try the Phase 0 pipeline by hand: `sudo ./bin/meridian-agent --iface <veth>`
attaches the counter and tails decoded flow events to stdout.

Generated eBPF bindings (`bpf/*_bpfel.go`/`.o`) and `vmlinux.h` are
**committed**; `make verify-gen` (and CI) regenerates and fails on any diff.

## Repository map

| Path | Contents |
|---|---|
| `bpf/` | eBPF C sources, shared headers (`include/meridian_*.h` — the frozen cross-boundary contract), committed bpf2go bindings. |
| `cmd/meridian-agent/` | Node agent binary (Phase 0 cut: load + attach + ring tail). `meridian-control` and the `meridian` CLI arrive in Phases 3/6. |
| `internal/agent/` | Agent internals: `bpfobj` (sole pin opener), `telemetry` (ring consumer); `datapath`, `xds`, `svid`, … arrive per phase. |
| `pkg/wire/` | Shared cross-boundary contracts (leaf package; stdlib only). |
| `docs/` | [ARCHITECTURE.md](docs/ARCHITECTURE.md) · [subsystem specs](docs/subsystems/) · [ADRs](docs/adr/README.md). |
| `test/` | `harness/` (netns fixtures, reaper, WaitUntil), `bpf/` (T2), `integration/` (T3), `vm/` (Lima). |

## Documentation

- **Specification:** [PRD_Meridian_eBPF_Service_Mesh.md](PRD_Meridian_eBPF_Service_Mesh.md)
- **Plan:** [ROADMAP.md](ROADMAP.md) · **Phase 0:** [PHASE0_CHECKLIST.md](PHASE0_CHECKLIST.md) · **Phase 1:** [PHASE1_PLAN.md](docs/PHASE1_PLAN.md) · **Phase 2:** [PHASE2_PLAN.md](docs/PHASE2_PLAN.md) ([tickets](docs/PHASE2_TICKETS.md) · [gates](docs/PHASE2_GATES.md))
- **Architecture:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Netns debug scripts:** [docs/NETNS_SCRIPTS.md](docs/NETNS_SCRIPTS.md)
- **Contributing / commit traceability:** [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- **Subsystems:** [eBPF](docs/subsystems/01-ebpf.md) · [Agent](docs/subsystems/02-agent.md) ·
  [Control plane](docs/subsystems/03-control-plane.md) · [SPIFFE PKI](docs/subsystems/04-spiffe.md) ·
  [Node proxy](docs/subsystems/05-node-proxy.md) · [Observability](docs/subsystems/06-observability.md)
