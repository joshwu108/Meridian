# Active Ticket

ID: MER-79

Title: A-3 — agent ADS client + xDS→CommitPlan translation (land policy in the kernel)

Objective:
Build the production agent-side ADS client (`internal/agent/xds`) that streams from
`meridian-control`, decodes the CC-2 contract via `internal/cc2`, and **applies**
the resulting snapshot to the kernel maps via the existing `datapath.Writer` —
replacing the MER-55 in-memory stub on the agent side. This is the second half of
A-3 (the MER-72 split) and the last code before the MER-73 exit gate (REST→kernel
< 500 ms). The server already emits CC-2 on CDS+EDS (MER-78) and the writer's
`Apply` order already matches ADR-0008 — so this ticket is the client + the
snapshot→`CommitPlan` diff.

Stay in scope: the `internal/agent/xds` ADS client + the snapshot→CommitPlan diff
+ their tests. Reuse the MER-55 `stub_agent` stream/ACK-NACK/reconnect shape and
`internal/cc2` for decode. Do NOT modify the ADS server/stub (MER-78), the codec
(`internal/cc2`), the `datapath.Writer` (its `Apply` is done), MER-73 (the gate),
MER-71 (A-2), or PKI.

Dependencies:
- MER-78 (server emits CC-2 on CDS+EDS) `343bc59`; `internal/cc2` codec `04ba285`;
  MER-54 (ADS transport) `0ff966d`; MER-55 (stub, the stream reference) `fe453b5`;
  `datapath.Writer` (D17 sole `wire`↔`bpf` translator, `Apply(ctx, wire.CommitPlan)`).
- Binding contracts: ADR-0008 (CDS=policy/EDS=identity; **kernel commit order**
  identity-adds → policy-adds → policy-removes → identity-deletes, already enforced
  by `datapath.Writer.Apply`; ACK only after a snapshot is fully applied; NACK +
  hold last-known-good on any failure — never transiently widen, CC-5). depguard
  `wire-bpf-bridge`: `internal/agent/xds` must NOT import `bpf/` (it depends on the
  `datapath.Writer` interface, the sole bpf writer).

Acceptance Criteria:
1. `internal/agent/xds`: an ADS client that opens a single bidi
   `StreamAggregatedResources` to `meridian-control`, subscribes to the resource
   types, and on each push decodes via `internal/cc2` (CDS→`[]wire.PolicyRule`,
   EDS→`[]wire.Identity`), accumulating a latest-wins full snapshot.
2. The client **diffs** the new snapshot against the last-applied state into a
   `wire.CommitPlan` (IdentityUpserts/Deletes, PolicyUpserts/Deletes) and applies
   it via the injected `datapath.Writer`. It **ACKs only after Apply succeeds**;
   on a decode/contract/apply error it **NACKs (error_detail) and holds the
   last-applied state**; on control-plane disconnect it keeps last-known-good and
   reconnects (jittered). No `bpf/` import (depguard).
3. Tests (`internal/agent/xds`, host): bufconn against a real MER-54 server +
   MER-78 codec with a fake/in-memory `datapath.Writer` — prove decode→diff→apply,
   ACK-after-apply, NACK-holds-last-good on a contract violation, a policy
   add+delete propagating as the right `CommitPlan`, and reconnect. Table-driven
   where natural; `-race` clean.
4. A T3 Lima integration test (isolated window — instrument competing-proc
   detection, the dual-loop collision corrupts shared runs) proving a snapshot
   pushed from the control plane lands in the real kernel `policy_map`/`identity_map`
   via the client + production `datapath.Writer`. (The < 500 ms end-to-end assertion
   is MER-73's gate; here just prove the write is correct.)
5. `go build ./...` clean; `go vet ./...` clean; `go test -race ./internal/...`
   green (MER-54/55/56/78 + cc2 stay green); `go mod tidy` no diff; depguard clean.
6. After commit, `git status` clean; `make check-commits` passes (MER-79 ref).

Files Expected To Change:
- internal/agent/xds/client.go        (new — ADS client: stream, decode via cc2, diff, apply, ACK/NACK, reconnect)
- internal/agent/xds/diff.go          (new — snapshot→wire.CommitPlan diff; or fold into client.go)
- internal/agent/xds/client_test.go   (new — bufconn + fake Writer)
- test/integration/rest_to_kernel_apply_test.go (new — T3 Lima: snapshot lands in kernel maps)

Required Tests:
- `go test -race ./internal/agent/xds/...`          → client decode/diff/apply/ACK/NACK/reconnect green
- `go test -race ./internal/...`                    → MER-54/55/56/78 + cc2 stay green
- `limactl shell meridian -- make test-integration` → snapshot lands in kernel maps (isolated window)
- `go build ./...` / `go vet ./...` / `go mod tidy` → clean; depguard clean
- `make check-commits`                              → MER-79 commit-linkage satisfied

Commit Message:
feat(agent): MER-79 A-3 ADS client + xDS→CommitPlan translation — land CC-2 policy in the kernel
