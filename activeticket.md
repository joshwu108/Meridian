# Active Ticket

ID: MER-78

Title: CC-2 server/stub adoption — wire ADS server + stub onto internal/cc2 (dedupe codec; emit CDS+EDS)

Objective:
Make the ADS server and the MER-55 stub speak the frozen CC-2 codec (ADR-0008 §2)
already implemented in `internal/cc2` (`04ba285`). Swap the MER-54 server's
resource builder off the opaque interim `[]wire.PolicyRule`-in-`BytesValue` blob
onto per-resource CC-2 `Any`s — emitting policy on the **CDS** channel **and**
identity on the **EDS** channel — and update the stub decode to match. This is the
control-plane half of A-3; it is fully host-testable (no Lima) and unblocks the
agent client (MER-79). It also **removes the duplicate codec** the dual-loop
collision left at `internal/control/ads/codec.go`.

Stay in scope: canonicalize on `internal/cc2`; the server resource builder; the
stub decode; the three ADS test files; the duplicate-codec removal. Do NOT build
the agent ADS client / datapath translation (MER-79), MER-71 (A-2), or PKI. Do NOT
change the ADS version/nonce transport (MER-54) or `internal/cc2`'s API.

Dependencies:
- MER-72 CC-2 codec (`internal/cc2`) — DONE `04ba285`. MER-54 (ADS server) `0ff966d`,
  MER-55 (stub) `fe453b5`, MER-56 (CP-3 gate) `2898a75`.
- Binding contract: ADR-0008 (per-resource `Any`; envelope `{schema_version,kind,
  spec}`; CDS=PolicyRule, EDS=Identity; LDS/RDS reserved versioned-but-empty, the
  agent/stub must tolerate empty L7 channels without NACK). depguard
  `control-no-dataplane` (internal/control may import `internal/cc2` + `pkg/wire`;
  not `bpf/`/agent).

Acceptance Criteria:
1. **Dedupe:** delete `internal/control/ads/codec.go` + `internal/control/ads/codec_test.go`
   (the `bfe0c58` duplicate); `internal/cc2` is the single CC-2 codec. `go build`/`go vet`
   clean; no dangling references.
2. `internal/control/ads/server.go` `resourcesFor`: emit **one CC-2 `Any` per
   resource** via `cc2.EncodePolicyRule` on `ClusterType` (CDS, from `ListPolicies`)
   and `cc2.EncodeIdentity` on `EndpointType` (EDS, from `ListIdentities`); other
   channels stay empty. No more bare-JSON blob.
3. `internal/control/ads/stub_agent.go`: decode each resource via `cc2.Decode*`
   per channel (policies on CDS, identities on EDS — validate identities even though
   the stub need not store them), NACK on any decode/contract violation; ACK
   otherwise. The stub keeps surfacing `Snapshot().Policies` for CP-3.
4. Update `server_test.go`, `stub_agent_test.go`, `conformance_test.go` off the old
   blob format onto the CC-2 codec (e.g. build expected resources via `cc2.Encode*`,
   decode via `cc2.Decode*`). **MER-56 (CP-3) `TestADSConformanceGate_MER56` stays
   green**, incl. the REST→stub < 500 ms propagation and NACK/stale-nonce paths.
5. `go build ./...` clean; `go vet ./...` clean; `go test -race ./internal/control/...`
   green (MER-53/54/55/56 + CP-2 stay green); `go mod tidy` no diff; depguard clean.
6. After commit, `git status` clean; `make check-commits` passes (MER-78 ref).

Files Expected To Change:
- internal/control/ads/codec.go          (DELETE — duplicate of internal/cc2)
- internal/control/ads/codec_test.go     (DELETE — duplicate)
- internal/control/ads/server.go         (resourcesFor → cc2, CDS policy + EDS identity)
- internal/control/ads/stub_agent.go     (decode → cc2 per channel)
- internal/control/ads/server_test.go    (expected resources via cc2)
- internal/control/ads/stub_agent_test.go (decode-table → cc2)
- internal/control/ads/conformance_test.go (raw-stream payloads → cc2)

Required Tests:
- `go test -race ./internal/control/...`  → ADS suite + CP-3 green on the cc2 codec
- `go build ./...` / `go vet ./...` / `go mod tidy` → clean
- `make check-commits`                    → MER-78 commit-linkage satisfied

Commit Message:
feat(control): MER-78 CC-2 server/stub adoption — emit CDS+EDS via internal/cc2; dedupe codec
