# Active Ticket

ID: MER-68

Title: Make `check-gate-skips` deterministic — reap kernel state between privileged gates

Objective:
Fix the gate-verification harness so the "0 skips / 0 failures across the 9 armed
gates" certification is **reproducible** on Lima 5.15. Today `make check-gate-skips`
is non-deterministic for the `bpf`/`integration` gates: it runs each gate as a
separate `go test` process but never reaps the kernel state the datapath
deliberately persists across exit (pinned maps, TC filters, cgroup attachments,
TPROXY rules — ARCHITECTURE lifecycle "Shutdown deliberately leaves…"), so
back-to-back gate processes inherit and collide on leftover state. This is the
**blocker of the truthful MER-59 Phase-2 EXIT**: the exit gate cannot cite a
reproducible/CI-confirmed green run until the harness is deterministic. The gates
themselves are genuinely green (canonical isolated targets pass reliably).

Stay in scope: the `checkgateskips` tool (and, if needed, the `check-gate-skips`
make target / a small harness helper). Do NOT change production datapath/agent
code — the persist-on-shutdown behavior is intentional (chaos-survival). Do NOT
weaken skip detection (MER-44 rule). Do NOT start MER-59 or touch its in-flight
WIP docs (README/ROADMAP/PHASE2_GATES edits in the working tree belong to MER-59).

Dependencies:
- None for the fix (gates are green via canonical targets `make test-bpf` /
  `make test-integration`, both exit 0 on Lima 5.15 with `-parallel 1`).
- BLOCKS MER-59 (Phase-2 EXIT). After this lands, MER-59 finalizes citing a clean
  `check-gate-skips` run + CI link, and references MER-68 by ID.
- Runtime: verify on the Lima `meridian` VM (5.15), network-off recipe
  `GOMODCACHE=/Users/joshuawu/go/pkg/mod GOFLAGS=-mod=mod GOPROXY=off`.

Acceptance Criteria:
1. `make check-gate-skips` is **deterministic on Lima 5.15**: green across **≥10
   consecutive runs** (and when a prior privileged suite has just run), all 9 armed
   gates reporting 0 skips / 0 failures — no order- or accumulation-dependent flake.
2. The fix **resets kernel state between privileged (`bpf`/`integration`) gate
   invocations** — e.g. `checkgateskips` shells the existing `make test-clean`
   (reap netns + `rm -rf /sys/fs/bpf/meridian-test`) before each privileged gate,
   and/or serializes privileged gates and pins each under a unique bpffs dir.
   Pure-Go gates skip the cleanup (no needless work).
3. Skip-integrity preserved (MER-44): the tool still **fails closed** on a genuine
   `t.Skip` or a genuine test failure — the cleanup must not mask a real red gate.
   Add/adjust a unit test for the tool's classification if practical.
4. No production datapath/agent/eBPF code changed; ADR-0004 frozen schema untouched.
5. `go build ./...` / `go vet ./...` clean; `make test-bpf` / `make test-integration`
   still green on Lima; `go mod tidy` no diff.
6. After commit, `git status` shows only the unrelated MER-59 WIP docs (do NOT
   commit those here); `make check-commits` passes (MER-68 ref).

Files Expected To Change:
- test/tools/checkgateskips/main.go      (reap state between privileged gates / serialize)
- test/tools/checkgateskips/*_test.go    (optional — assert fail-closed on real skip/fail)
- Makefile                                (optional — if cleanup is wired at the target level)

Required Tests:
- `for i in $(seq 10); do make check-gate-skips; done` on Lima 5.15 → green every run, 0 skips/0 failures
- `make test-bpf` / `make test-integration` (Lima) → still green (no regression)
- `go build ./...` / `go vet ./...` → clean
- `make check-commits` → MER-68 commit-linkage satisfied

Commit Message:
fix(gates): MER-68 deterministic check-gate-skips — reap kernel state between privileged gates
