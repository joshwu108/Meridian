# Active Ticket

ID: MER-53

Title: CP-1 slice — control-plane memory store + identity registry + REST skeleton

Objective:
Stand up the control-plane core that the ADS lane (MER-54 server → MER-55 stub →
MER-56 CP-3 gate → MER-59 Phase-2 EXIT) builds on. This is the first
control-plane ticket beyond the Phase-1 policy compiler (CP-2): an in-memory
`control.Store`, a monotonic identity registry (CC-3), and a REST surface that
accepts policy/service definitions and reports status. Pure distributed-systems
Go — no eBPF, no kernel, no agent internals; it parallels the eBPF lane and is
verifiable with `go test` (no VM required).

Stay in scope: store + identity + REST + the `meridian-control` entrypoint and
their unit tests. Do NOT start the ADS gRPC server (MER-54) or touch the eBPF /
agent / frozen-schema code. The compiled-policy wire types live in `pkg/wire`
(reuse them); the policy compiler already exists in `internal/control`.

Dependencies:
- Phase-2 entry: MER-34 green (SATISFIED). No other open-ticket dependency.
- Binding contracts: CC-3 (control plane is the SOLE allocator of the cluster
  uint32 identity space — monotonic, never reused within a process lifetime,
  ID 0 reserved for unknown). depguard `control-no-dataplane`: `internal/control`
  must NOT import `bpf/` or `internal/agent/*` — stay control-plane + `pkg/wire`.
- `control.Store` interface ALREADY EXISTS in `internal/control/doc.go` (package
  `control`, identity + policy CRUD over `wire` types). Reconcile with it — do NOT
  define a second `control.Store`. MER-54's `Watch()`-driven push depends on a
  change-notify hook, so EXTEND the existing interface with a `Watch()`/subscription
  seam now; the in-memory impl lives under `internal/control/store`.

Acceptance Criteria:
1. `internal/control/store/memory.go`: in-memory `control.Store`. **Reconcile with
   the EXISTING `control.Store` interface in `internal/control/doc.go`** (identity +
   policy CRUD over `wire.Identity`/`wire.PolicyRule`/`wire.PolicyRuleKey`) — extend
   that interface with the `Watch()` change-notify seam (channel or callback) for
   MER-54; do NOT author a parallel divergent Store. ("service" in the REST surface
   maps onto `wire.Identity`, which already carries `Name`.) Concurrency-safe;
   immutable snapshots returned to callers (no shared mutable state).
2. `internal/control/identity/registry.go`: allocates monotonic `uint32`
   identities, **never reused within a process lifetime** (CC-3); ID 0 reserved
   for unknown and never allocated; lookups by name↔ID are stable; allocation is
   concurrency-safe.
3. `internal/control/rest/server.go`: serves `POST`/`GET /policies`,
   `POST`/`GET /services`, and `GET /status`; validates request bodies against a
   schema and **fails closed** with a 4xx + structured error envelope on bad
   input; success responses use a consistent envelope.
4. `cmd/meridian-control/main.go`: starts the REST server on a `--listen` flag
   (default e.g. `:8080`); clean startup/shutdown; no panics on SIGTERM.
5. Unit tests (`server_test.go` + registry/store tests): ID-allocation invariants
   (monotonic, no reuse across allocate/“delete”, ID 0 never handed out,
   concurrency), REST 4xx on malformed/invalid bodies, and a happy-path CRUD
   round-trip. Table-driven where natural.
6. `go build ./...` clean; `go vet ./...` clean; `go test ./internal/control/...`
   green (the existing CP-2 conformance + compiler tests must stay green);
   depguard clean (no `bpf/`/agent imports from `internal/control`).
7. After commit, `git status` is clean and `make check-commits` passes (MER-53 ref).

Files Expected To Change:
- internal/control/doc.go                (extend existing Store with a Watch()/subscription seam — reconcile, don't duplicate)
- internal/control/store/memory.go       (new — in-memory Store impl + Watch seam)
- internal/control/store/memory_test.go  (new — CRUD + Watch unit tests)
- internal/control/identity/registry.go  (new — monotonic uint32 allocator, CC-3)
- internal/control/identity/registry_test.go (new — allocation invariants)
- internal/control/rest/server.go        (new — REST handlers + validation)
- internal/control/rest/server_test.go   (new — 4xx + CRUD round-trip)
- cmd/meridian-control/main.go           (wire REST server + --listen flag)

Required Tests:
- `go test ./internal/control/...` → new store/identity/rest tests green; CP-2 still green
- `go build ./...`                 → meridian-control builds with --listen
- `go vet ./...`                   → clean (depguard control-no-dataplane satisfied)
- `make check-commits`             → MER-53 commit-linkage satisfied

Commit Message:
feat(control): MER-53 CP-1 memory store + identity registry + REST skeleton
