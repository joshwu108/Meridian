# Active Ticket

ID: MER-72

Title: A-3 — ADS client + xDS→CommitPlan translation (adopt CC-2; land policy in the kernel)

Objective:
Make the agent consume real control-plane config: a live ADS client that streams
from `meridian-control`, decodes the **CC-2 wire contract** (ADR-0008), and
translates xDS resources into `identity_map` / `policy_map` writes — replacing the
MER-55 in-memory stub on the agent side. This is the critical-path item toward the
MER-73 exit gate (REST→kernel < 500 ms). It also lands the CC-2 proto and swaps
the MER-54 server's resource builder off the interim JSON-in-`BytesValue`
encoding (D21) onto the frozen `meridian.config.v1` protos (ADR-0008 / D22).

Stay in scope: the `meridian.config.v1` proto, the server resource-builder swap,
the agent ADS client (`internal/agent/xds`), and the xDS→CommitPlan translation
(`internal/agent/datapath`) + their tests. Do NOT start MER-73 (the end-to-end
gate), MER-71 (A-2 netlink), or PKI. Do NOT change the ADS version/nonce transport
(MER-54) or the frozen kernel schema (ADR-0004).

Dependencies:
- MER-70 / ADR-0008 (CC-2 wire contract) — frozen `0054b5f`. MER-54 (ADS server)
  `0ff966d`, MER-55 (stub, the decode reference) `fe453b5`. MER-53 (REST+store) ✅.
- Binding contracts: ADR-0008 (type_url mapping CDS=policy/EDS=identity, Meridian
  protos, **commit ordering** identity-adds → policy-adds → policy-removes →
  identity-deletes, ACK-after-commit, never transiently widen); D17 (`datapath`
  is the **sole** `wire`↔`bpf` translator); depguard `wire-bpf-bridge`
  (`internal/agent/xds` must NOT import `bpf/`).
- Runtime: the translation/commit path is Linux/Lima (real maps); the ADS client
  + proto decode are unit-testable on any host (bufconn, as MER-54/55 do).

Acceptance Criteria:
1. `meridian.config.v1` proto authored (per ADR-0008 §2: `PolicyRule` + `Identity`
   with the frozen field numbers) and generated bindings committed; the MER-54 ADS
   server resource builder swapped from JSON-in-`BytesValue` to these protos on the
   CDS (policy) / EDS (identity) channels. **MER-56 (CP-3) conformance stays green**
   (handshake unchanged; only the resource encoding changes — update the MER-55
   stub decode accordingly).
2. `internal/agent/xds`: an ADS client — single bidi `StreamAggregatedResources`
   to `meridian-control`, subscribes to the resource types, decodes per CC-2,
   **ACKs only after the snapshot is applied**, **NACKs (holds last-known-good)**
   on a decode/contract/range violation; enforces last-known-good on control-plane
   disconnect (jittered reconnect). No `bpf/` import (depguard).
3. `internal/agent/datapath`: xDS resources → `wire` → `CommitPlan` → kernel map
   writes in the **ADR-0008 commit order** (identities before referencing policies;
   remove-allow before add on shrink — never transiently widen). `datapath` is the
   sole importer of both `pkg/wire` and generated `bpf/` types (D17).
4. Tests: T1 decode/translate unit tests (proto→wire→CommitPlan, ordering,
   range-violation→NACK) on any host; a T3 Lima test that a pushed snapshot lands
   in the kernel `policy_map`/`identity_map` (the MER-73 gate arms the < 500 ms
   end-to-end assertion separately — here just prove correctness of the write).
5. `go build ./...` clean; `go vet ./...` clean; `go test -race ./internal/...`
   green (MER-54/55/56 stay green); `make test-bpf`/`make test-integration` green on
   Lima; `go mod tidy` no diff; depguard clean.
6. After commit, `git status` clean; `make check-commits` passes (MER-72 ref).

Files Expected To Change:
- pkg/wire/ (or a new proto pkg) meridian.config.v1 `.proto` + generated bindings
- internal/control/ads/server.go        (resource builder → CC-2 protos)
- internal/control/ads/stub_agent.go     (decode → CC-2 protos; keep CP-3 green)
- internal/agent/xds/*.go                (ADS client + decode)
- internal/agent/datapath/*.go           (xDS→CommitPlan→map writes, commit order)
- internal/agent/xds/*_test.go, internal/agent/datapath/*_test.go

Required Tests:
- `go test -race ./internal/...`                 → agent xds/datapath + control ads green
- `limactl shell meridian -- make test-integration` → snapshot lands in kernel maps (isolated window)
- `go build ./...` / `go vet ./...` / `go mod tidy` → clean
- `make check-commits`                            → MER-72 commit-linkage satisfied

Commit Message:
feat(agent): MER-72 A-3 ADS client + xDS→CommitPlan translation (adopt CC-2 protos)
