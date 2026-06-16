# Active Ticket

ID: MER-55

Title: ADS agent stub — in-memory xDS client over loopback gRPC

Objective:
Build the agent-side ADS client *stub* that speaks the xDS handshake against the
MER-54 server: connect over loopback gRPC, subscribe to the resource types,
decode the pushed resources, ACK what it accepts, and NACK on a contract
violation. This is the counterparty the CP-3 conformance gate (MER-56) drives
through connect → receive → ACK → reconnect, and the first end-to-end exercise
of the server's version/nonce loop. Pure distributed-systems Go — no eBPF, no
kernel, no real agent internals; verifiable with `go test` (no VM).

Stay in scope: the stub client, its decode/ACK/NACK logic, a debug snapshot
accessor, and unit tests. Do NOT build the CP-3 conformance gate (MER-56), arm
any manifest gate, or touch the eBPF / agent-datapath / frozen-schema code.
Reuse the MER-54 server, `internal/control`, and `pkg/wire`; the stub lives
beside the server in `internal/control/ads` and may use unexported server
helpers/constants (e.g. the type URLs, the payload contract).

Dependencies:
- MER-54 (ADS server: version/nonce state machine + ordered push) — CLOSED
  `0ff966d`. The stub connects to its `StreamAggregatedResources`.
- Binding contract: the MER-54 server encodes Meridian policy as a
  JSON-marshalled `[]wire.PolicyRule` packed in a `wrapperspb.BytesValue` Any on
  the **Cluster** channel only (other channels are versioned-but-empty). The stub
  MUST decode that exact contract and MUST **NACK** (send `error_detail`, do not
  advance accepted version) on a contract violation — undecodable resource,
  wrong/foreign payload, or a resource on a channel it cannot interpret.
- depguard `control-no-dataplane`: `internal/control/ads` must NOT import `bpf/`
  or `internal/agent/*` — stay control-plane + `pkg/wire` + grpc/xDS only.

Acceptance Criteria:
1. `internal/control/ads/stub_agent.go`: a `StubAgent` that, given a gRPC
   `ClientConn` (or an ADS client), opens `StreamAggregatedResources`, subscribes
   to the resource types (initial empty-nonce requests), and runs a receive loop.
2. On each received `DiscoveryResponse`: decode the resources per the MER-54
   contract; on success send a well-formed **ACK** (echo `version_info` +
   `response_nonce`, no `error_detail`); on a decode/contract failure send a
   **NACK** (`error_detail` set, `version_info` reverted to last-accepted) and
   keep the stream alive. ACK/NACK nonce handling mirrors the server's
   expectations so the server's `classify` settles correctly.
3. The stub exposes the last-accepted snapshot for inspection (e.g. a
   concurrency-safe `Snapshot()` returning the decoded `[]wire.PolicyRule` +
   accepted version) and logs received snapshots for debugging. No data races.
4. Clean teardown: the receive loop exits on context cancel / stream EOF without
   leaking goroutines; a `Close()`/cancel path is provided.
5. Unit tests (`stub_agent_test.go`): drive the stub against a real MER-54 server
   over `bufconn` through **connect → receive initial → ACK → store change →
   receive update → ACK**, and a **reconnect** cycle (new stream re-subscribes
   and re-receives current state). Include at least one **NACK-on-contract-
   violation** case (server pushes something the stub rejects, or assert the
   NACK path via a contract-violating payload) and assert the stub surfaces the
   decoded policy. Table-driven where natural.
6. `go build ./...` clean; `go vet ./...` clean; `go test -race
   ./internal/control/...` green (MER-53 + MER-54 + CP-2 stay green); `go mod
   tidy` leaves no diff; depguard clean (no `bpf/`/agent imports).
7. After commit, `git status` is clean and `make check-commits` passes (MER-55 ref).

Files Expected To Change:
- internal/control/ads/stub_agent.go        (new — in-memory ADS client stub)
- internal/control/ads/stub_agent_test.go   (new — connect/receive/ACK/reconnect + NACK)

Required Tests:
- `go test -race ./internal/control/ads/...` → stub connect/ACK/reconnect/NACK green
- `go test -race ./internal/control/...`     → MER-53 + MER-54 + CP-2 stay green
- `go build ./...`                           → control plane builds
- `go vet ./...`                             → clean (depguard control-no-dataplane satisfied)
- `make check-commits`                       → MER-55 commit-linkage satisfied

Commit Message:
feat(control): MER-55 ADS agent stub — in-memory xDS client over loopback gRPC
