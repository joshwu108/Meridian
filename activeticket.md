# Active Ticket

ID: MER-72

Title: A-3 — ADS client + xDS→CommitPlan translation (adopt CC-2 versioned-JSON codec; land policy in the kernel)

Objective:
Make the agent consume real control-plane config: a live ADS client that streams
from `meridian-control`, decodes the **CC-2 wire contract** (ADR-0008 §2, the
**versioned-JSON codec** — revised by MER-77, NO protoc), and translates xDS
resources into `identity_map`/`policy_map` writes — replacing the MER-55 in-memory
stub on the agent side. Critical-path item toward the MER-73 exit gate (REST→kernel
< 500 ms). It also freezes the codec and swaps the MER-54 server's resource builder
off the opaque interim `[]wire.PolicyRule`-in-`BytesValue` blob (D21) onto the
frozen ADR-0008 versioned-JSON schema (D22).

Stay in scope: the CC-2 codec (encode+decode of the ADR-0008 §2 JSON resources),
the server resource-builder swap, the agent ADS client (`internal/agent/xds`), and
the xDS→CommitPlan translation (`internal/agent/datapath`) + their tests. Do NOT
add protoc/proto (ADR-0008 §2 is stdlib `encoding/json` now). Do NOT start MER-73
(the end-to-end gate), MER-71 (A-2 netlink), or PKI. Do NOT change the ADS
version/nonce transport (MER-54) or the frozen kernel schema (ADR-0004).

Dependencies:
- MER-77 (ADR-0008 §2 revised to no-protoc versioned JSON) `d7f232a`; MER-70/ADR-0008
  `0054b5f`. MER-54 (ADS server) `0ff966d`, MER-55 (stub, decode reference) `fe453b5`.
- Binding contracts: ADR-0008 (type_url mapping CDS=policy/EDS=identity; the §2
  versioned-JSON `PolicyRule`/`Identity` schemas; fail-closed decode —
  `DisallowUnknownFields` + integer-width validation mirroring ADR-0004; **commit
  ordering** identity-adds → policy-adds → policy-removes → identity-deletes, ACK
  after commit, never transiently widen). D17 (`datapath` is the **sole**
  `wire`↔`bpf` translator); depguard `wire-bpf-bridge` (`internal/agent/xds` must
  NOT import `bpf/`).
- Runtime: the translation/commit path is Linux/Lima (real maps); the ADS client +
  codec are unit-testable on any host (bufconn, as MER-54/55 do). **No protoc.**

Acceptance Criteria:
1. A CC-2 **codec** implementing ADR-0008 §2 (encode + decode of the versioned-JSON
   `PolicyRule` (CDS) / `Identity` (EDS) resources wrapped in `Any`→`BytesValue`),
   with the fail-closed decode rules (`DisallowUnknownFields`, integer-width checks,
   version gate). The MER-54 ADS server resource builder is swapped from the opaque
   interim blob onto this codec on the CDS (policy) + EDS (identity) channels; the
   MER-55 stub decode is updated to match. **MER-56 (CP-3) conformance stays green**
   (handshake unchanged; only the resource encoding changes).
2. `internal/agent/xds`: an ADS client — single bidi `StreamAggregatedResources` to
   `meridian-control`, subscribes to the resource types, decodes per CC-2, **ACKs
   only after the snapshot is applied**, **NACKs (holds last-known-good)** on a
   decode/contract/range violation; enforces last-known-good on control-plane
   disconnect (jittered reconnect). No `bpf/` import (depguard).
3. `internal/agent/datapath`: xDS resources → `wire` → `CommitPlan` → kernel map
   writes in the **ADR-0008 commit order** (identities before referencing policies;
   remove-allow before add on shrink — never transiently widen). `datapath` is the
   sole importer of both `pkg/wire` and generated `bpf/` types (D17).
4. Tests: T1 codec + translate unit tests (JSON→wire→CommitPlan, ordering,
   unknown-field/range-violation→NACK) on any host; a T3 Lima test that a pushed
   snapshot lands in the kernel `policy_map`/`identity_map` (the MER-73 gate arms the
   < 500 ms end-to-end assertion separately — here just prove the write is correct).
   Verify the Lima T3 in an **isolated window** (instrument competing-proc detection;
   the dual-loop collision corrupts shared Lima runs).
5. `go build ./...` clean; `go vet ./...` clean; `go test -race ./internal/...` green
   (MER-54/55/56 stay green); `make test-integration` green on Lima; `go mod tidy`
   no diff; depguard clean.
6. After commit, `git status` clean; `make check-commits` passes (MER-72 ref).

Files Expected To Change:
- internal/control/ads/codec.go (new — CC-2 versioned-JSON encode/decode, ADR-0008 §2)
- internal/control/ads/server.go        (resource builder → CC-2 codec)
- internal/control/ads/stub_agent.go     (decode → CC-2 codec; keep CP-3 green)
- internal/agent/xds/*.go                (ADS client + decode)
- internal/agent/datapath/*.go           (xDS→CommitPlan→map writes, commit order)
- internal/control/ads/*_test.go, internal/agent/{xds,datapath}/*_test.go

Required Tests:
- `go test -race ./internal/...`                    → agent xds/datapath + control ads green
- `limactl shell meridian -- make test-integration` → snapshot lands in kernel maps (isolated window)
- `go build ./...` / `go vet ./...` / `go mod tidy` → clean
- `make check-commits`                              → MER-72 commit-linkage satisfied

Commit Message:
feat(agent): MER-72 A-3 ADS client + xDS→CommitPlan translation (adopt CC-2 versioned-JSON codec)
