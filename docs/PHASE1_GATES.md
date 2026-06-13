# Phase 1 gate definitions (MER-44)

Phase 1 ships six **gates** — integration or property suites whose green
status is a merge blocker. A gate is **not** green when its tests are skipped:
`t.Skip` stubs let CI report success while the enforcement path is unproven
(MER-42 finding).

## Gate inventory

| Gate ID | Ticket | Suite | Package / file |
|---------|--------|-------|----------------|
| P1.1 | MER-18 | Verdict matrix ≡ reference evaluator | `test/bpf/verdict_test.go` |
| P1.2 | MER-29 | Live policy integration (agent stub) | `test/integration/policy_test.go` |
| P1.3 | MER-21 | Geneve two-node identity + policy | `test/integration/geneve_test.go` |
| CP-2 | MER-24 | Compiler ≡ reference property | `internal/control/conformance_test.go` (planned) |
| O-2 | MER-32 | Denied-flows + metrics assertion | `test/integration/metrics_test.go` (planned) |
| EXIT | MER-34 | ADR-0004 freeze + doc reconciliation | references all gates above |

## Skip-integrity rule (MER-44)

**An armed gate may be declared green only when:**

1. Its manifest row in `test/gates/manifest.txt` has `armed=yes`.
2. `make check-gate-skips` (or CI `check-gate-skips` step) reports **0 skips**
   for that test — verified by parsing `go test -json` for `"Action":"skip"`.
3. The suite also reports **0 failures** on the 5.15 CI target.

Do **not** land a gate with `t.Skip("waiting on MER-…")` while `armed=yes`.
Flip `armed` to `yes` only after upstream blockers are merged and the suite
runs for real.

### Checking locally

```bash
# After bpf + integration tiers (Linux, root):
make test-bpf test-integration
make check-gate-skips
```

### Adding a new gate stub

1. Add the test file with a stable `Test…Gate_MERxx` name.
2. Append a row to `test/gates/manifest.txt` with `armed=no`.
3. Land upstream work, remove all `t.Skip` calls, flip `armed=yes`.

CI runs `make check-gate-skips` in the privileged job after T2/T3 tests.
