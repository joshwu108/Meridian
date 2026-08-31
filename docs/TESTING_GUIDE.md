# Meridian Testing Guide

This document explains how to test Meridian: the four-tier test strategy, how to run each tier, what each tier covers, and how to debug failures. It is the companion to `docs/DEVELOPMENT_GUIDE.md`.

---

## 1. The four-tier test strategy

Meridian has four test tiers, numbered T1–T4. Each tier has different requirements and runs in different environments:

| Tier | Tag | Environment | What it tests |
|------|-----|-------------|---------------|
| **T1** Unit | *(none)* | Any OS, no root | Pure-Go logic: policy compiler, reference evaluator, ADS codec, CA, identity registry, xDS client |
| **T2** BPF | `bpf` | Linux ≥ 5.15, root | eBPF programs: `bpf_prog_test_run` synthetic packet injection, verifier-clean load |
| **T3** Integration | `integration` | Linux ≥ 5.15, root | Live netns: full-stack end-to-end including real kernel TC attach, ADS propagation, SOCKMAP |
| **T4** Bench/Chaos | `e2e` | Dedicated isolated host | Performance benchmarks, chaos suite (agent kill, partition, cert expiry), K8s demo |

**Key insight:** T1 runs anywhere — macOS, CI, your laptop. T2 and T3 require a Linux kernel with root; on macOS, use the bundled Lima VM. T4 requires a dedicated pinned-CPU host to avoid noise in benchmark numbers.

---

## 2. Running the tests

### Prerequisites

```bash
# Check that all required tools and kernel features are present:
make doctor
```

On macOS (for T2/T3), start the Lima VM first:

```bash
limactl start --name=meridian test/vm/meridian.yaml
limactl shell meridian
# Then run make targets inside the VM shell
```

### T1 — unit tests (run anywhere)

```bash
make test-unit
# Equivalent to:
go test -race ./...
```

These are the tests you run most often during development. They run in < 30 seconds and need no root. The `-race` flag enables Go's race detector — it finds concurrent accesses to shared data that could cause bugs.

**What they cover:**
- `internal/reference/evaluator_test.go` — the reference policy evaluator (oracle)
- `internal/control/compiler_test.go` — policy compiler ≡ reference evaluator property test
- `internal/control/store/memory_test.go` — store semantics
- `internal/control/identity/registry_test.go` — ID monotonicity, idempotency, CC-3
- `internal/control/ads/*_test.go` — ADS server + stub, CP-3 conformance gate
- `internal/cc2/codec_test.go` — CC-2 versioned-JSON encode/decode
- `internal/agent/xds/client_test.go` — ADS client state machine
- `internal/agent/datapath/translate_test.go` — wire→kernel translation
- `internal/control/ca/*_test.go` — CA hierarchy, CSR validation, bootstrap credential

### T2 — BPF program tests (Linux + root)

```bash
make test-bpf
# Equivalent to:
sudo go test -race -tags bpf ./test/bpf/...
```

BPF tests use `bpf_prog_test_run`, a kernel API that lets you feed synthetic packets to an eBPF program and inspect the verdict — without any real network traffic. You can test "does a TCP packet from identity 1 to identity 2 on port 80, with an ALLOW policy, get TC_ACT_OK?" without setting up any network namespaces.

**What they cover:**
- Verdict correctness for all (allow, deny, redirect) × (TCP, UDP, unknown protocol) combinations
- Unknown-identity posture (fail-closed vs. fall-open)
- Geneve identity option parsing (cross-node identity)
- SOCKMAP negative gate (P2.1-N / MER-49): proves DENY sockets are NEVER inserted into SOCKHASH

**Important:** Each BPF test loads a fresh instance of the eBPF programs into the kernel. Tests must clean up their pin files under `/sys/fs/bpf/meridian-test/<runID>/<test>/` — the test harness does this via `t.Cleanup`.

### T3 — integration tests (Linux + root + network)

```bash
make test-integration
# Equivalent to:
sudo go test -race -tags integration ./test/integration/...
```

Integration tests simulate a real multi-node deployment using Linux network namespaces. Each "node" is a netns containing an agent, TPROXY rules, and node-side pod vetches. "Pods" are child netns. Nodes are joined by uplink vetches on a host bridge.

**What they cover:**
- Live policy integration: REST → ADS → agent → kernel map, measured < 500 ms (MER-73 gate)
- Veth attach lifecycle: pod appears → agent TC-attaches in < 100 ms, no leaks (MER-71 gate)
- SOCKMAP byte integrity: 1 MiB transfer verifies byte-for-byte over the redirect path (MER-51 gate)
- Denied-flow metrics: denied packets appear in the `denied_flows_map` (MER-32 gate)
- Geneve two-node: identity option is encoded on egress, decoded on ingress, policy enforced (MER-21 gate)

**Resource cleanup:** Every resource is namespaced with `mrdn-<runID>-*`. The `TestMain` reaper runs before and after the suite. If a test crashes and leaves netns or BPF pins behind, the next run's `TestMain` reaper cleans them up.

### T4 — benchmarks and chaos (dedicated host)

```bash
make test-e2e
# Equivalent to:
sudo go test -race -tags e2e ./test/integration/...
```

T4 tests are NOT PR gates. They run nightly on a dedicated pinned-CPU host.

**What they cover:**
- `TestSockmapBench_MER52`: SOCKMAP latency vs. baseline for short connect+first-byte flows. (Finding: no intra-node latency win on kernel 5.15 for short flows — the SOCKMAP path is justified by correctness and mTLS-offload-readiness, not latency.)
- Chaos suite (Phase 8): agent SIGKILL mid-stream, control-plane partition, certificate expiry during partition.

---

## 3. The gate manifest and CI

### What is the gate manifest?

`test/gates/manifest.txt` is the authoritative list of CI merge-blocker tests. Each row describes one gate:

```
armed  build_tags  package_path  test_name_regex
```

- `armed=yes` means CI fails if the test is *skipped* (in addition to failing). A test can't be skipped to make CI pass — you'd have to unskip it.
- `armed=no` means the test is tracked but skips are allowed (used while a gate's implementation is in progress).

### How to check gate status locally

```bash
make check-gate-skips
```

This runs `checkgateskips`, which iterates the manifest and verifies each test runs without being skipped and without failing. On Linux+root, it also reaps leftover netns/pins before each privileged gate to avoid cross-test contamination (the MER-68 determinism fix).

```
# Expected output on a fully green tree:
11/11 armed gates green, 0 skips, 0 failures
```

### The CI pipeline (GitHub Actions `ci.yml`)

CI runs on `ubuntu-22.04` (Linux kernel 5.15-azure) with `sudo`. Steps:

1. `go build ./...` — build everything
2. `go vet ./...` — static analysis
3. `go test -race ./...` — T1 (unit tests; excludes T2/T3 by build tags)
4. `sudo go test -race -tags bpf ./test/bpf/...` — T2
5. `sudo go test -race -tags integration ./test/integration/...` — T3
6. `make check-gate-skips` — verify the gate manifest is fully green

CI runs on every PR. A PR must not be merged if any CI step fails.

---

## 4. Writing new tests

### T1 tests (preferred for new logic)

If you can test it without the kernel, write a T1 test. This includes:
- Any new Go function in `internal/control`, `internal/agent/xds`, `internal/cc2`, `pkg/wire`
- Any new CA or crypto logic
- Any new wire format changes

Use standard Go table-driven tests:

```go
func TestMyFeature(t *testing.T) {
    tests := []struct {
        name  string
        input string
        want  string
        wantErr bool
    }{
        {"basic case", "foo", "FOO", false},
        {"empty", "", "", true},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            got, err := MyFeature(tc.input)
            if (err != nil) != tc.wantErr {
                t.Fatalf("error = %v, wantErr = %v", err, tc.wantErr)
            }
            if got != tc.want {
                t.Fatalf("got %q, want %q", got, tc.want)
            }
        })
    }
}
```

Use `t.Run` for subtests so failures pinpoint exactly which case failed.

### T2 tests (new eBPF programs or policy logic)

New eBPF program behavior requires a `bpf_prog_test_run` test. The test harness is in `test/bpf/`. Use `test/harness` for resource management.

```go
//go:build bpf

package bpf_test

func TestNewProgramBehavior(t *testing.T) {
    // Load the program
    objs, err := bpftest.LoadObjects(t, ...)
    // Inject a synthetic packet
    // Assert the verdict
}
```

Always clean up with `t.Cleanup`:

```go
objs, err := LoadObjects(...)
t.Cleanup(func() { objs.Close() })
```

### T3 tests (end-to-end behavior)

End-to-end tests go in `test/integration/`. They set up real netns and run the actual agent binary.

Key rules:
- Use `test/harness.WaitUntil(deadline, condition)` — never `time.Sleep`
- Namespace all resources: `mrdn-<testRunID>-<testname>`
- Register all cleanup via `t.Cleanup` *before* bring-up (so cleanup runs even if setup panics)
- Use `t.Log` generously — integration test failures are hard to debug without logs

### Adding a new gate

When implementing a gate:
1. Add a row to `test/gates/manifest.txt` with `armed=no` when the ticket is created
2. Flip to `armed=yes` when the test is implemented and green on the 5.15 target
3. Add evidence to `docs/PHASE*_GATES.md`

Never flip `armed=yes` without a real green run — green-washing is a MER-44 violation.

---

## 5. Using the reference evaluator for policy tests

`internal/reference/evaluator.go` is the policy oracle — a pure-Go implementation of the policy lookup logic that is deliberately simple and obviously correct. All policy tests should compare their expected output against what the reference evaluator says.

The CP-2 gate (`TestCompilerMatchesReferenceProperty`) runs a property-based test: for random policy snapshots, the compiler's output must produce the same verdicts as the reference evaluator. This catches compiler bugs before they reach the kernel.

When writing policy tests:

```go
ref := reference.NewEvaluator(policies)
got := compiler.Compile(policies)
// For every (src, dst, port, proto, direction):
//   ref.Verdict(src, dst, port, proto, dir) == got[key].Action
```

---

## 6. Testing the CA (PKI-1)

The gate is `TestCAPrimitivesGate_MER74` in `internal/control/ca/ca_test.go`. It is a T1 test — pure Go, no root needed.

For new PKI tests, use `ca.NewTestAuthority("cluster.local")` to get an ephemeral Root+Intermediate. Don't use real production keys in tests.

Key things to always test for CA code:
- **Happy path**: chain verifies against `auth.TrustPool()` using `x509.VerifyOptions`
- **Wrong curve**: P-256 for node CSR and P-384 for workload CSR should be rejected
- **Multiple SANs**: any DNS, IP, or email SAN alongside the SPIFFE URI must be rejected
- **Trust domain mismatch**: a SPIFFE ID from a different trust domain must be rejected

---

## 7. Debugging test failures

### T1 failures

Run with `-v` to see all subtests:

```bash
go test -v -race -run TestMyFeature ./internal/...
```

Add `t.Log` statements to the failing test. Remember the race detector (`-race`) is always on — a data race is a real bug, not a test issue.

### T2 failures

The most common cause is the verifier rejecting a new BPF program. Get the verifier log:

```bash
sudo go test -v -tags bpf -run TestVerdictMatrix ./test/bpf/...
```

The cilium/ebpf library prints verifier errors when program load fails. The error message shows the exact eBPF instruction that triggered the rejection and why.

If the test loads cleanly but fails on verdict: add a `bpf_printk` call to your eBPF C (visible in `cat /sys/kernel/debug/tracing/trace_pipe`). Remember to remove debug prints before committing.

### T3 failures

Integration test failures almost always have one of these causes:

1. **Race with another test** (rare after MER-68): use `make check-gate-skips` in an isolated window
2. **WaitUntil deadline exceeded**: the condition was never met. Add more `t.Log` around the condition and check what state the map/agent is actually in
3. **Leaked netns from a previous run**: run `make check-gate-skips` which reaps before each gate
4. **Kernel version difference**: behavior changed between 5.15.x point releases (the MER-82 pattern). Check if the failure is new since a kernel update; bisect if needed

To add more debugging to a T3 test:

```bash
sudo go test -v -tags integration -run TestRestToKernelGate_MER73 ./test/integration/...
```

Use `ip netns list | grep mrdn` to see running test namespaces. If a test hangs, attach to the netns:

```bash
sudo ip netns exec mrdn-<runID>-<testname> bash
```

### CI failures vs. local passes

If a test passes locally but fails in CI, check:
- Kernel version: CI uses `ubuntu-22.04` (5.15-azure); Lima uses 5.15.x (may differ in minor patch)
- Root: CI runs T2/T3 with `sudo`; if you ran locally without root and it "passed", the test was skipped
- `check-gate-skips`: a test that was skipped appears to pass but is actually absent

---

## 8. Benchmarking

Benchmarks are T4 (`e2e` tag) and run only on the dedicated host. Do not run them in CI (the results are meaningless due to shared CPU resources).

When running a benchmark:
1. Ensure no other root processes are running in the VM (check with `ps aux`)
2. Run at least 10 iterations (the harness does this automatically)
3. Report the coefficient of variation (CV). If CV > 5%, discard and rerun
4. Report honest results. A "no win" is a valid finding (see `test/integration/testdata/sockmap_bench.json`)

**The SOCKMAP result as an example:** The MER-52 benchmark measured SOCKMAP redirect on kernel 5.15 for short connect+first-byte flows. The result was:
- p50: within noise (~+6%)
- p99: consistent regression (~+280%)

The correct conclusion is "SOCKMAP provides no latency benefit for short flows on 5.15; its value is correctness and mTLS-offload-readiness." The incorrect conclusion would be to report it as a win or skip reporting because it wasn't the hoped-for result. Report what you measured, honestly.

---

## 9. Quick reference

```bash
# Run all unit tests (anywhere)
make test-unit

# Run BPF tests (Linux + root)
make test-bpf

# Run integration tests (Linux + root)
make test-integration

# Run benchmarks (Linux + root + dedicated host)
make test-e2e

# Check all CI gates are green and not skipped
make check-gate-skips

# Verify generated eBPF bindings match source (determinism check)
make verify-gen

# Build all binaries
make build

# Check toolchain and kernel requirements
make doctor

# Start Lima VM (macOS)
limactl start --name=meridian test/vm/meridian.yaml
limactl shell meridian
```
