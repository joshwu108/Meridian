# Active Ticket

ID: MER-73

Title: A-3 GATE — REST→kernel policy_map < 500 ms end-to-end (Phase-3 exit gate)

Objective:
Arm the Phase-3 exit gate: prove the whole A-3 spine lands a policy in the kernel
within the ROADMAP week-5/6 budget. A REST `POST /policies` on `meridian-control`
must reach the **real kernel `policy_map`/`identity_map`** — via store → ADS server
→ `xds.Client` → `datapath.Writer` — in **under 500 ms**, measured by polling
(`WaitUntil`, not sleep). This is the end-to-end proof that the codec (MER-72) +
server/stub adoption (MER-78) + agent client (MER-79) work against real maps, and
the success criterion the ROADMAP names for Phase 3.

Stay in scope: the integration test wiring the existing components end-to-end + the
manifest gate row. Do NOT modify the control plane, ADS server/client, codec, or
the `datapath.Writer` (all done). Do NOT start MER-71 (A-2), PKI, or the MER-76 EXIT.

Dependencies:
- **MER-78 ✅** (server emits CC-2 on CDS+EDS) `343bc59`, **MER-79 ✅** (agent
  `xds.Client` decode→diff→apply) `d604a4d`, MER-53 ✅ (REST + store), MER-54 ✅
  (ADS transport), `datapath.Writer` (MER-15, real `policy_map`/`identity_map`).
- **NOTE — dependency reconciliation:** the PHASE3_TICKETS join listed `{71,72}`,
  but the gate measures **config propagation** (REST→…→map write), which is the
  A-3 lane only. **MER-71 (A-2 veth/netlink lifecycle) is NOT required** — it
  governs TC-program attach, not map propagation. The gate wires the components
  directly; the full `meridian-agent` binary (with netlink) is not needed.
- Runtime: Linux + root + 5.15. **Verify on the Lima `meridian` VM in an ISOLATED
  window** — instrument competing-proc detection (the dual-loop collision corrupts
  shared Lima runs, proven in MER-68/58/52).

Acceptance Criteria:
1. `test/integration/rest_to_kernel_test.go` (build tag `integration`): wire
   `store.NewMemory()` → `rest.NewServer` (httptest) + `ads.NewServer(store)`
   (bufconn) + `xds.NewClient(conn, writer)` where `writer = datapath.NewWriter`
   over **real** `identity_map`/`policy_map` loaded via `bpfobj` (LoadCounter/
   LoadTcIngress, isolated pin dir). Seed an identity so the policy resolves.
2. `POST /policies` a valid rule; assert the rule appears in the kernel
   `policy_map` (read back the map) **within 500 ms**, measured with a polling
   `WaitUntil(deadline, cond)` — **not** `time.Sleep`. Record the observed latency.
3. **NACK-on-malformed holds last-good:** a malformed/contract-violating push does
   not change the kernel maps (the client NACKs; CC-5). Assert the map is unchanged.
4. Arm the manifest: add the gate row to `test/gates/manifest.txt`
   (`yes integration ./test/integration/... TestRestToKernelGate_MER73`); the test
   must never `t.Skip` under root on 5.15; `make check-gate-skips` → 0 skips across
   the now-**10** armed gates (verify in an isolated window).
5. `go build ./...` clean; `go vet ./...` clean; `make test-integration` green on
   Lima (incl. the new gate); `go mod tidy` no diff; depguard clean (the test may
   use `bpfobj`/`datapath`/`harness`).
6. After commit, `git status` clean; `make check-commits` passes (MER-73 ref).

Files Expected To Change:
- test/integration/rest_to_kernel_test.go   (new — REST→kernel <500 ms T3 gate)
- test/gates/manifest.txt                     (arm the CP-? / A-3 gate row)

Required Tests:
- `make test-integration` (Lima 5.15, ISOLATED window) → TestRestToKernelGate_MER73 green; rule in policy_map < 500 ms; malformed→no map change
- `make check-gate-skips` (Lima)                       → 0 skips across 10 armed gates
- `go build ./...` / `go vet ./...` / `go mod tidy`    → clean
- `make check-commits`                                  → MER-73 commit-linkage satisfied

Commit Message:
test(agent): MER-73 arm A-3 exit gate — REST→kernel policy_map < 500 ms end-to-end
