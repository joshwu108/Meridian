# Active Ticket

ID: MER-56

Title: CP-3 GATE — ADS conformance suite + REST→stub <500 ms propagation

Objective:
Arm the CP-3 gate: a permanent, always-on conformance suite that drives the
MER-55 stub against the MER-54 ADS server through the full xDS lifecycle, plus an
end-to-end propagation proof that a REST `POST /policies` reaches the stub as
updated compiled resources in **under 500 ms**. This is the third Phase-2 gate
(after P2.1-N and P2.2) and a MER-59 EXIT join dependency — the last critical-path
item on the Platform lane. It is the first wiring of the whole control-plane
spine: REST (MER-53) → `control.Store` → ADS server (MER-54) → stub (MER-55).
Pure distributed-systems Go — no eBPF, no kernel, no VM; runs in plain `go test`.

Stay in scope: the conformance test, its regression seed data, and arming the
manifest row. Do NOT modify the ADS server/stub/REST production code except a
minimal, justified seam if the wiring genuinely requires it (prefer using the
existing public constructors). Do NOT start MER-59 (EXIT) or the MER-67 ADR.

Dependencies:
- MER-55 (ADS agent stub) — CLOSED `fe453b5`. MER-54 (ADS server) — CLOSED
  `0ff966d`. MER-53 (REST + store) — CLOSED `849f4a6`. All three are wired here.
- Gate integrity (MER-44): the manifest row may flip to `armed=yes` ONLY when the
  suite is green with **zero skips**; the conformance test must never `t.Skip`
  (it is pure Go and always runnable — no root/kernel/VM guard applies).
- depguard `control-no-dataplane`: the test stays control-plane + `pkg/wire` +
  grpc/xDS; no `bpf/` or `internal/agent/*`.

Acceptance Criteria:
1. `internal/control/ads/conformance_test.go` defines `TestADSConformanceGate_MER56`
   driving the stub↔server over `bufconn` through, at minimum:
   a. **initial snapshot** — stub receives + ACKs the seeded policy set;
   b. **policy add** — `store.PutPolicy` (or REST POST) propagates a new rule;
   c. **policy delete** — `store.DeletePolicy` propagates removal;
   d. **NACK recovery** — after a NACK, the server holds last-known-good and a
      subsequent valid change still propagates (stream stays healthy);
   e. **out-of-order / stale nonce ignored** — a stale-nonce request causes no
      server state change (use a raw client stream for this sub-case, since the
      stub only ever answers the latest push);
   f. **reconnect with last-known version** — a fresh stream re-subscribes and
      re-receives current state (including changes made while disconnected).
2. **<500 ms propagation:** wire the MER-53 `rest.Server` (httptest) + shared
   `control.Store` + MER-54 ADS server + MER-55 stub; `POST /policies`, then
   assert the stub's `Snapshot()` reflects the new rule within **500 ms**,
   measured by polling (a `waitUntil(deadline, cond)` helper), **not** `time.Sleep`.
3. `test/gates/manifest.txt`: flip the CP-3 row from `armed=no` to `armed=yes`
   (`yes '' ./internal/control/ads/... TestADSConformanceGate_MER56`).
4. Regression seed data committed under `internal/control/ads/testdata/` (the
   policy/identity fixtures the suite loads), referenced by the test.
5. `make check-gate-skips` reports **0 skips** across all **9** armed gates
   (the 8 existing + CP-3); the new test contributes no skip.
6. `go build ./...` clean; `go vet ./...` clean; `go test -race
   ./internal/control/...` green (MER-53/54/55 + CP-2 stay green); `go mod tidy`
   leaves no diff; depguard clean.
7. After commit, `git status` is clean and `make check-commits` passes (MER-56 ref).

Files Expected To Change:
- internal/control/ads/conformance_test.go   (new — CP-3 conformance + <500 ms gate)
- internal/control/ads/testdata/             (new — committed regression seeds)
- test/gates/manifest.txt                     (flip CP-3 row armed=no → armed=yes)

Required Tests:
- `go test -race ./internal/control/ads/...`        → TestADSConformanceGate_MER56 green, 0 skips
- `go test -race ./internal/control/...`            → MER-53/54/55 + CP-2 stay green
- `make check-gate-skips`                           → 0 skips across 9 armed gates
- `go build ./...` / `go vet ./...`                 → clean (depguard satisfied)
- `make check-commits`                              → MER-56 commit-linkage satisfied

Commit Message:
test(control): MER-56 arm CP-3 gate — ADS conformance + REST→stub <500 ms propagation
