# Meridian Implementation Roadmap

Derived from [PRD_Meridian_eBPF_Service_Mesh.md](PRD_Meridian_eBPF_Service_Mesh.md). The project is decomposed into six subsystems, each specified in detail under `docs/subsystems/`:

| # | Subsystem | One-line scope | PRD phases | Detail |
|---|---|---|---|---|
| 1 | **eBPF data plane** | TC policy enforcement, SOCKMAP redirect, maps, ring buffer, CO-RE toolchain | 0–2 | [01-ebpf.md](docs/subsystems/01-ebpf.md) |
| 2 | **Node agent** | Program lifecycle, veth attachment, xDS→map translation, SVID lifecycle, TPROXY plumbing | 1, 3, 4 | [02-agent.md](docs/subsystems/02-agent.md) |
| 3 | **Control plane** | ADS/xDS server, policy store + compiler, identity registry, REST, etcd, K8s watchers | 3, 7 | [03-control-plane.md](docs/subsystems/03-control-plane.md) |
| 4 | **SPIFFE PKI** | CA hierarchy, SVID issuance/rotation, Workload API, node bootstrap, trust bundle | 4 | [04-spiffe.md](docs/subsystems/04-spiffe.md) |
| 5 | **Node proxy** | mTLS termination/origination, CONNECT tunneling, L7 policy, circuit breaking | 4–5 | [05-node-proxy.md](docs/subsystems/05-node-proxy.md) |
| 6 | **Observability** | Ring-buffer pipeline, Prometheus, OTel traces, live CLI streams | 0–1, 5, 8 | [06-observability.md](docs/subsystems/06-observability.md) |

The CLI (Phase 6) and Kubernetes packaging (Phase 7) are thin consumers of these six and are scheduled inside the relevant subsystems rather than treated as subsystems themselves.

---

## Dependency graph

```text
                 ┌──────────────────┐
                 │ 1. eBPF data     │  ← no Meridian deps; needs only kernel + toolchain
                 │    plane         │
                 └───┬──────────┬───┘
        map schemas │           │ pinned maps, redirect verdicts
        (contract)  │           │
   ┌────────────────▼──┐    ┌───▼───────────────┐
   │ 3. Control plane  │    │ 2. Node agent     │ ← hub: consumes 1,3,4; feeds 5,6
   │  (vs agent stub)  │◄───┤  (ADS client,     │
   └───┬───────────────┘ADS │   map writer)     │
       │ identity registry  └───┬───────────┬───┘
       │                        │ Workload  │ L7 rules,
   ┌───▼───────────────┐        │ API sock  │ ring buffer
   │ 4. SPIFFE PKI     ├────────▼───┐   ┌───▼───────────────┐
   │  (CA in control,  │ 5. Node    │   │ 6. Observability  │
   │   lifecycle in    │    proxy   ├──►│  (L4 + L7 merge)  │
   │   agent)          │            │   └───────────────────┘
   └───────────────────┘────────────┘
```

Three properties of this graph drive the schedule:

1. **The eBPF subsystem has zero Meridian dependencies** — it starts first and its *map schemas* (not its runtime) are the contract everything else compiles against. Freeze the schemas at the end of Phase 1.
2. **The control plane and SPIFFE PKI are buildable entirely against fakes** (an in-memory agent stub, synthetic CSRs, a `go-spiffe` fake workload client) — they parallelize with eBPF/agent work from day one if staffing allows.
3. **The node proxy is the most-blocked component** — it needs the eBPF redirect + original-destination plumbing (CC-1), an agent-served Workload API socket, and a CA that can mint two certs. Its pure parts (L7 matcher, rotation logic, circuit breaker) should be built early in isolation so integration is the only late work.

## Build order (mapped to PRD phases, ~13 weeks)

| Week | PRD phase | Workstream A (kernel/data path) | Workstream B (distributed systems) | Exit gate |
|---|---|---|---|---|
| 1 | 0 | eBPF toolchain spine; packet counter + ring readback (O-1) | Control-plane storage, identity registry, REST (CP-1) | `make ebpf` deterministic; program loads verifier-clean |
| 2–3 | 1 | Full TC parser + policy verdicts (`bpf_prog_test_run` first, then live netns); agent stub (A-1); flow metrics (O-2) | Reference evaluator + policy compiler + fuzz harness (CP-2) | Verdicts ≡ reference evaluator; **map schemas frozen (ADR)** |
| 4 | 2 | Gated `sock_ops` + `sk_msg` redirect; integrity + benchmark | ADS server vs agent stub, conformance suite (CP-3) | Denied flow never SOCKMAP-redirected; policy-change-to-stub < 500 ms |
| 5–6 | 3 | Agent netlink lifecycle (A-2); ADS client + translation (A-3) | CA primitives + node bootstrap (PKI-1/2) | REST → kernel map < 500 ms measured end-to-end |
| 7–8 | 4 | TPROXY plumbing (A-5); proxy redirect/echo prototype (P4.1) | SVID issuance + rotation + Workload API (PKI-3/4); mTLS on ADS (CP-4); proxy mTLS in/out (P4.2–4.4) | Full A→proxy→proxy→B mTLS; unauthorized C rejected; **CC-1 resolved before this phase starts** |
| 9 | 5 | — | L7 policy + circuit breaker (P5.1–5.2); OTLP + flow/http watch streams (O-3/4, P5.3) | Success criteria 5–6 (live flow + HTTP telemetry) |
| 10 | 6 | CLI: `policy`, `cert`, `flows`, `http`, `map`, `status` commands over existing agent/control APIs | | All PRD §5 Phase 6 commands functional |
| 11–12 | 7 | DaemonSet/Helm packaging | etcd backend, K8s informers, CRD, TokenReview bootstrap, webhook (CP-5, PKI-2b) | K8s e2e demo: frontend+backend, L7 policy, `http watch` |
| 13 | 8 | Fuzzing, chaos suite (agent kill, control-plane partition, cert expiry), benchmarks, `meridian doctor` (A-6, O-5) | | All §11 success criteria measured and documented |

**Critical path:** eBPF Phase 1 → schema freeze → agent translation (A-3) → CC-1/TPROXY → proxy mTLS (P4.x) → L7 (P5.x). The control plane and PKI run off-path against fakes; their only on-path obligations are the schema/metadata contract (week 3) and a two-cert CA (week 7).

## Cross-cutting decisions (resolve early; each warrants an ADR)

These emerged from subsystem analysis and are *not* explicit in the PRD:

- **CC-1 — Original-destination recovery (blocking, highest leverage).** `bpf_redirect()`/`bpf_redirect_neigh()` to the proxy port does **not** preserve the original destination for a normal `accept()`; the PRD glosses over this. Decide before Phase 4: **TPROXY + `IP_TRANSPARENT`** (recommended — matches Istio ztunnel; proxy recovers dst via `getsockname()`) vs eBPF DNAT-to-loopback + a pinned `orig_dst_map`. Forces work on the agent (rule installation), proxy (transparent listeners), and possibly the eBPF schema (new map).
- **CC-2 — Compiled-policy wire contract.** The byte layout of `policy_key_t`/`policy_verdict_t` and the xDS metadata schema carrying verdicts, `l7_required`, identity IDs, and L7 rules is *the* contract between control plane, agent, and kernel. Freeze before Phase 3 completes.
- **CC-3 — Numeric identity allocation.** The control plane is the **sole allocator** of the cluster-global uint32 identity space (Geneve carries it across nodes). Monotonic, never reused within a control-plane lifetime; ID 0 reserved for unknown. Resolve the PRD's value-size inconsistency (8 B in §4.3 vs `__u32` in §6.3) to `__u32`.
- **CC-4 — Single node bootstrap credential.** One node identity authenticates both the ADS stream and SVID issuance; standalone mode uses an operator-provisioned cert, K8s mode uses ServiceAccount projected tokens + TokenReview to break the bootstrap circularity.
- **CC-5 — Fail-closed posture, including the unknown-identity question.** Agents enforce last-known-good config on control-plane loss; connections without a valid SVID are refused near expiry; NACK/partial config never widens allows. **Open security question:** the PRD's skeleton passes through unknown identities (`TC_ACT_OK`) — confirm whether that posture is acceptable or must tighten to default-deny on attach. Also: SOCKMAP eligibility is a policy property (a verdict flag), not a perf toggle — absent the flag, no SOCKHASH insertion.
- **CC-6 — Single-sourced structs and telemetry correlation.** Every cross-boundary struct (esp. `flow_event`, where the PRD's C and Go versions disagree) is defined once in a C header with the Go mirror generated by bpf2go. L4 flow events and L7 spans correlate on `(src_identity, dst_identity, dst_port)` + timestamp window.

## Top risks across the system

Each subsystem file carries its full ranked list; the five that can sink the project:

1. **Original-destination plumbing missing (eBPF R3 / proxy R1)** — interception is non-functional without it. Mitigate by making CC-1 a Phase-4 entry gate with a no-TLS echo prototype.
2. **SOCKMAP policy/mTLS bypass (eBPF R2)** — a wrongly inserted socket silently skips encryption and L7 policy. Mitigate with verdict-gated `sock_ops` insertion plus permanent negative tests in CI.
3. **Policy compiler/translation divergence (control plane #1, agent #3)** — zero-false-allow/deny is a stated success criterion. Mitigate by building the reference evaluator *first* and property-testing compiler ≡ reference from week 2, not deferring to Phase 8.
4. **BPF verifier rejection (eBPF R1)** — schedule risk more than correctness risk. Mitigate with incremental program growth and `bpf_prog_test_run` CI on the exact target kernel (Ubuntu 22.04 / 5.15).
5. **Certificate rotation failure (PKI #1, PRD-rated Critical)** — both directions: expiry outage and silently accepting near-expired certs. Mitigate with the 2/3-TTL window, make-before-break swaps, fail-closed near expiry, and a chaos test covering control-plane-down-during-rotation.

## First three concrete actions

1. Write the two gating ADRs: *original-destination mechanism (CC-1)* and *compiled-policy + identity-ID wire contract (CC-2/CC-3)*.
2. Stand up the eBPF toolchain spine (Phase 0.1): repo scaffolding, `make ebpf`, no-op TC program loading verifier-clean on a 5.15 VM, CI job running `bpf_prog_test_run`.
3. Start the reference policy evaluator + property-test harness — it is pure Go, has no dependencies, and everything correctness-critical is measured against it.
