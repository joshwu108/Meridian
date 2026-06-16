# Active Ticket

ID: MER-52

Title: P2.2-BENCH — intra-node SOCKMAP latency benchmark (nightly T4)

Objective:
Measure the actual latency benefit of the SOCKMAP redirect fast path: a same-node
eligible flow with SOCKMAP redirect vs the same flow without it, reporting p50/p99
connect + first-byte latency. This is the last open dependency of the Phase-2 EXIT
gate (MER-59 ← {49 ✅, 51 ✅, 56 ✅, **52**}); it does not gate PRs but its results
must exist and be committed before MER-59 can declare Phase 2 complete. Report
honestly: a measurable win with numbers, OR explicitly flag "no win on
<kernel>" with the numbers that show it. Do NOT green-wash a win that isn't there.

Stay in scope: the benchmark test, its committed result fixture, and (if needed) a
nightly invocation hook. This is a **T4 `e2e`-tagged** test — it must NOT run in
the PR `integration`/`bpf` suites and must NOT arm a manifest gate row (it is not a
merge gate). Do NOT start MER-59 (EXIT) or MER-58. Reuse the MER-51 integrity
harness (production `bpfobj` loaders + `attach` managers + `test/harness`) to build
the redirect path — do not hand-roll SOCKMAP attach.

Dependencies:
- MER-51 (P2.2 integrity gate) — CLOSED `f7642c9`. Provides the same-node SOCKMAP
  redirect harness (production `bpfobj`/`attach` + `test/harness`) this benchmark
  reuses to establish an eligible redirected flow.
- Runtime: Linux + root + a 5.15 kernel (SOCKMAP/sock_ops/sk_msg). **Verify on the
  Lima `meridian` VM** (`MERIDIAN_IN_LIMA=1` or `go test -tags e2e -exec sudo`),
  not on the darwin host. This is NOT a pure-Go ticket.
- depguard `wire-bpf-bridge`: tests are exempt; reuse `bpfobj`/`attach`/`harness`
  as MER-51 does — do not import `bpf/` outside the allowed test seams.

Acceptance Criteria:
1. `test/integration/sockmap_bench_test.go` with `//go:build e2e` — a benchmark
   (or `-run`-able measurement test) that, on a same-node loopback flow:
   a. establishes an **eligible** (SOCKMAP-redirected) flow via the production
      attach path and measures connect + first-byte latency over N iterations;
   b. measures the **baseline** (no SOCKMAP redirect) same-node flow identically;
   c. computes **p50 and p99** for both and the delta.
2. **Honest verdict:** the test emits both distributions and a verdict —
   "SOCKMAP win: p50 −X%, p99 −Y%" OR "no measurable win on <kernel>: <numbers>".
   It must not assert a hard win (the result is data, not a pass/fail gate); it
   fails only on harness/measurement error, never on "win too small".
3. Results committed to `test/integration/testdata/sockmap_bench.json` (schema:
   kernel/uname, iterations, sockmap p50/p99, baseline p50/p99, delta, verdict,
   timestamp), regenerated from a real Lima 5.15 run.
4. The `e2e` tag is excluded from the PR suites: `make test-integration`
   (`-tags=integration`) and `make test-bpf` (`-tags=bpf`) do NOT compile or run
   this file; `make check-gate-skips` is unaffected (no new armed row). Optionally
   add a `make bench-sockmap`/`test-e2e` target or document the nightly invocation.
5. `go build ./...` clean; `go vet ./...` clean; PR suites stay green and skip-free
   (the e2e file is tag-excluded, so it cannot contribute a PR-suite skip);
   `go mod tidy` leaves no diff.
6. After commit, `git status` is clean and `make check-commits` passes (MER-52 ref).

Files Expected To Change:
- test/integration/sockmap_bench_test.go         (new — //go:build e2e benchmark)
- test/integration/testdata/sockmap_bench.json   (new — committed real Lima 5.15 result)
- Makefile                                        (optional — nightly bench-sockmap/test-e2e target)

Required Tests:
- `go test -tags e2e -exec sudo -run TestSockmapBench ./test/integration/...` (Lima 5.15) → measures p50/p99, writes result JSON
- `go test -tags=integration ./test/integration/...` (PR suite) → unaffected; e2e file tag-excluded
- `go build ./...` / `go vet ./...`               → clean
- `make check-commits`                            → MER-52 commit-linkage satisfied

Commit Message:
test(ebpf): MER-52 P2.2-BENCH intra-node SOCKMAP latency benchmark (nightly e2e)
