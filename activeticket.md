# Active Ticket

ID: MER-54

Title: ADS server — version/nonce state machine + ordered xDS push

Objective:
Stand up the control-plane ADS (Aggregated Discovery Service) server that pushes
compiled policy/identity state to agents over a single bidirectional xDS stream.
This is the consumer of the MER-53 `control.Store` `Watch()` seam: a store change
triggers recompute + an ordered push, and the server tracks per-(node, type_url)
`version_info`/`nonce` so ACKs advance the accepted version and NACKs hold
last-known-good (CC-5 fail-closed: a NACK or partial config never widens allows).
Pure distributed-systems Go — no eBPF, no kernel, no agent internals; verifiable
with `go test` (no VM).

Stay in scope: the ADS gRPC server, its version/nonce bookkeeping, and the
`Watch()`-driven push, plus their unit tests. Do NOT build the agent-side stub
(MER-55) or the CP-3 conformance gate (MER-56). Reuse `internal/control` (Store,
Compile) and `pkg/wire`; depend on the Store via its interface.

Dependencies:
- MER-53 (CP-1 store + identity registry + REST) — CLOSED `849f4a6`. The Store
  `Watch()` seam this server consumes now exists.
- Binding contracts: CC-5 (NACK/partial config never widens allows; hold
  last-known-good on a bad push). depguard `control-no-dataplane`:
  `internal/control/ads` must NOT import `bpf/` or `internal/agent/*` — stay
  control-plane + `pkg/wire` + third-party (gRPC/xDS) only.
- Research-and-reuse (mandatory): before hand-rolling the xDS state machine,
  evaluate `github.com/envoyproxy/go-control-plane` (battle-tested ADS server
  + version/nonce + snapshot cache). Adopt or port it rather than writing
  net-new if it meets the contract; record the choice in a short note.

Acceptance Criteria:
1. `internal/control/ads/versioning.go`: per-(node, type_url) `version_info` +
   `nonce` bookkeeping. ACK (request nonce == last sent, no error_detail)
   advances the accepted version; NACK (error_detail present) holds the prior
   accepted version; a stale/unknown nonce is ignored (no state change). Pure,
   concurrency-safe, table-test-friendly.
2. `internal/control/ads/server.go`: `StreamAggregatedResources` bidirectional
   handler. Subscribes to the Store `Watch()`; on change, recompiles and pushes.
   Push ordering: CDS before EDS, LDS before RDS. A malformed/unresolvable
   resource yields a NACK path with `error_detail`; the server never pushes a
   config that widens allows on partial input (CC-5).
3. `go.mod`/`go.sum`: add the gRPC + xDS dependencies actually used (e.g.
   `google.golang.org/grpc`, `github.com/envoyproxy/go-control-plane`), pinned;
   `go mod tidy` clean.
4. Unit tests (`server_test.go` + versioning tests): T1 state-machine coverage of
   ACK-advances, NACK-holds-last-good, stale-nonce-ignored, and resubscribe;
   plus a `Watch()`-triggered push test (store mutation → ordered resources on
   the stream). Use an in-process / `bufconn` gRPC dialer — no real network.
   Table-driven where natural.
5. `go build ./...` clean (modulo the pre-existing `bpf/` C-source notice);
   `go vet ./...` clean; `go test -race ./internal/control/...` green (MER-53 +
   CP-2 conformance stay green); depguard clean (no `bpf/`/agent imports from
   `internal/control`).
6. After commit, `git status` is clean and `make check-commits` passes (MER-54 ref).

Files Expected To Change:
- internal/control/ads/versioning.go        (new — version/nonce state machine)
- internal/control/ads/versioning_test.go   (new — ACK/NACK/stale-nonce table tests)
- internal/control/ads/server.go            (new — StreamAggregatedResources + Watch push)
- internal/control/ads/server_test.go       (new — bufconn stream + ordered push)
- go.mod / go.sum                           (add pinned gRPC + xDS deps)

Required Tests:
- `go test -race ./internal/control/...` → new ads tests green; MER-53 + CP-2 stay green
- `go build ./...`                       → control plane + meridian-control build
- `go vet ./...`                         → clean (depguard control-no-dataplane satisfied)
- `make check-commits`                   → MER-54 commit-linkage satisfied

Commit Message:
feat(control): MER-54 ADS server — version/nonce state machine + ordered push
