# Meridian — Project Overview

This document is a concise, newcomer-friendly guide that condenses the repository's key design, architecture, build, and development information. It is intended for engineers who are new to the project and to eBPF-based data planes.

## 1) Executive summary

- Meridian is an eBPF-native service-mesh data plane: kernel-resident eBPF programs enforce identity- and policy-based L4 rules, optionally redirect L7 traffic to a per-node proxy for mTLS and HTTP policy, and export telemetry via a BPF ring buffer.
- A lightweight per-node `meridian-agent` loads/manages eBPF programs, applies compiled policy into eBPF maps, and talks to a control plane (`meridian-control`) using a small subset of xDS (gRPC) for policy, endpoints, and identity.
- Goals: minimal overhead, zero-copy intra-node communication via SOCKMAP, SPIFFE-based identity (SVIDs) with automatic rotation, Prometheus + OpenTelemetry observability.

## 2) High-level architecture

- Control plane: `meridian-control` (xDS, CA/PKI, policy store, REST admin).
- Node agent: `meridian-agent` (loads eBPF programs, watches interfaces, translates xDS → eBPF maps, serves Workload API to the node proxy).
- Data plane (per veth): TC ingress/egress eBPF programs, `sk_msg`/`sock_ops` programs for SOCKMAP, several eBPF maps for identity, policy, metrics, ring buffer for flow events.
- Node proxy: userspace Go proxy that terminates/initiates mTLS (SVIDs) and enforces L7 HTTP rules when policies indicate.

Diagram (simplified): control plane → gRPC ADS → agent (writes maps) → kernel eBPF programs → (optionally) node proxy → application

## 3) Key components in the repo (where to look first)

- Root: `README.md` (quickstart, quick map of repo)
- PRD & planning: `PRD_Meridian_eBPF_Service_Mesh.md`, `ROADMAP.md`, `PHASE0_CHECKLIST.md`
- Architecture & subsystems: `docs/ARCHITECTURE.md`, `docs/subsystems/01-ebpf.md`, `02-agent.md`, `03-control-plane.md`, `04-spiffe.md`, `05-node-proxy.md`, `06-observability.md`
- eBPF sources & headers: `bpf/` (C programs, `include/meridian_*.h`, `gen.go` for bpf2go)
- Binaries / entrypoints: `cmd/meridian-agent/`, `cmd/meridian-control/`, `cmd/meridian/` (CLI)
- Agent internals: `internal/agent/` (supervisor, bpfobj, telemetry, datapath, xds, svid, etc.)
- Tests & harness: `test/` (bpf tests, integration netns harness, vm/ for Lima), `Makefile` targets

## 4) eBPF programs & maps (core runtime concepts)

- Programs:
  - `tc_ingress` / `tc_egress`: parse packets, map lookups, policy verdict, redirect/drop/allow decisions.
  - `sk_msg` and `sock_ops`: SOCKMAP path for intra-node zero-copy redirect.
  - `sock_ops`: observe socket lifecycle to maintain the SOCKHASH.

- Important maps (shared kernel ↔ userspace):
  - `identity_map`: pod IP → numeric SPIFFE identity (u32)
  - `policy_map`: compiled rules keyed by (src_id, dst_id, dst_port, proto, direction)
  - `sockhash`/`sockmap`: socket redirect map for intra-node fast path
  - `flow_events` (RINGBUF): decision events sent to the agent consumer
  - `denied_flows_map`: recent denied flows for debugging

- Key behaviors:
  - Policy is compiled server-side → agent writes into `policy_map`.
  - L4 policy is enforced in kernel; L7-required traffic is redirected to node proxy.
  - SOCKMAP bypasses the kernel network stack; policy must guard eligibility.

## 5) Identity & mTLS (SPIFFE)

- The control plane issues SPIFFE SVIDs via the CA; agents rotate workload certs (short TTL, rotated at 2/3 lifetime).
- Identity propagation: `identity_map` in kernel for local IPs; cross-node source identity carried in a Geneve option on egress.
- Node proxy performs mTLS termination/origination for L7 or MTLS-required flows. eBPF steering + TPROXY or redirect plumbing ensures the proxy can recover original destination.

## 6) Build, quickstart, and common commands

Prereqs: Linux ≥ 5.10 (dev target Ubuntu 22.04 / 5.15); clang/LLVM (for BPF), libbpf-dev, bpftool, Go 1.22+. For macOS development, use the bundled Lima VM (see `test/vm/meridian.yaml`).

Common workflow (root of repo):

```bash
make doctor
make vmlinux       # generate kernel header (vmlinux.h)
make ebpf          # compile bpf/ C -> .o + bpf2go bindings
make build         # build binaries (agent etc.)
make test-unit
make test-bpf
make test-integration
```

Run an agent locally (Linux root):

```bash
sudo ./bin/meridian-agent --iface <veth>
```

## 7) Testing strategy & CI

- Unit tests (T1): pure Go logic (policy compiler, identity code, SVID rotation logic) run anywhere.
- BPF tests (T2): `bpf_prog_test_run` synthetic packet tests on Linux (verifier + logic correctness).
- Integration tests (T3): netns-based multi-node simulation for end-to-end flows.
- Bench & chaos (T4): performance and resilience tests on dedicated hardware.
- CI enforces deterministic `make ebpf`/`verify-gen` and runs T1+T2+fast-T3 subset on PRs.

## 8) Important design decisions & risks (what to learn first)

- Original-destination plumbing (TPROXY vs DNAT) is a critical cross-cutting decision — it affects how the node proxy recovers the application destination.
- BPF verifier constraints drive how C programs must be written (bounds checks, no unbounded loops, small stack frames).
- SOCKMAP correctness vs policy/mTLS bypass is high-risk — tests and gating are essential.
- Schema contract: cross-boundary headers in `bpf/include/meridian_types.h` are canonical; Go mirrors are generated via `bpf2go` (avoid drift).

## 9) Where to read next (recommended learning path)

1. `README.md` → quickstart and repo map
2. `PRD_Meridian_eBPF_Service_Mesh.md` → full goals, phases, and deep technical sections (Geneve, SOCKMAP, SVIDs)
3. `docs/ARCHITECTURE.md` → decisions, agent lifecycle, maps, and test harness
4. `docs/subsystems/01-ebpf.md` → low-level eBPF program and map contracts
5. `bpf/` → read `counter.c`, `tc_ingress.c` (when present) and `bpf/include/*.h` to learn contracts
6. `internal/agent/` → supervisor, `bpfobj`, `telemetry` consumer for how the agent wires to kernel
7. `test/` → harness and integration tests for hands-on experiments

## 10) Glossary (short)

- eBPF: in-kernel bytecode allowing programmable packet processing.
- TC: Linux Traffic Control hooks (ingress/egress) where eBPF programs attach.
- SOCKMAP/SOCKHASH: BPF maps for socket-level redirect (zero-copy intra-node).
- SVID: SPIFFE Verifiable Identity Document (X.509 certificate with SPIFFE URI).
- xDS/ADS: Envoy discovery APIs (Cluster/Endpoint/Listener/Route) used as a compact config protocol.
- TPROXY: Linux transparent proxy mechanism to preserve original destination for proxied sockets.

## 11) Next steps I can do for you

- Produce a PDF of this overview in the repo and attach it here (I will try to generate it with `pandoc` if available on the machine).
- Expand any subsection into a longer onboarding chapter (e.g., "eBPF for developers: getting started with the counter program" with step-by-step hands-on labs).

---

(Generated from `README.md`, `PRD_Meridian_eBPF_Service_Mesh.md`, `docs/ARCHITECTURE.md`, `PHASE0_CHECKLIST.md`, and `ROADMAP.md`.)
