# Active Ticket

ID: MER-57

Title: Agent cgroup + SOCKHASH attach path (production sock_ops / sk_msg)

Objective:
Move the Phase-2 SOCKMAP attach out of test-only code and into the production
agent. Today `sock_ops` (MER-48) and `sk_msg` (MER-50) are only ever attached by
the bpf test harness; the running agent attaches nothing. This ticket adds an
attach manager that loads the SockOps/SkMsg objects (sharing the agent's pinned
maps) and attaches `sock_ops` to a cgroup v2 (`BPF_CGROUP_SOCK_OPS`) and `sk_msg`
to the `sockhash` map fd (`BPF_SK_MSG_VERDICT`), wired into `meridian-agent`
behind a new `--cgroup` flag. It is the dependency the P2.2 gate (MER-51) needs:
that gate runs a two-pod-same-node transfer with the agent — not a test — owning
the SOCKMAP attach.

Scope: attach plumbing + agent flag + smoke ONLY. Do NOT modify `sock_ops.c`,
`sk_msg.c`, `meridian_helpers.h`, the frozen schema, or the existing TC attach
path beyond additive wiring. Do not implement the MER-51 integrity gate here.

Dependencies:
- MER-47 (DONE `70c52ad`): SockOps/SkMsg bpf2go bindings + `sockhash` map exist.
- MER-48 (DONE `77540ce`) / MER-50 (DONE `c699887`): the programs being attached.
- ADR-0007 (sock_ops sole writer / sk_msg sole reader of `sockhash`). The existing
  `internal/agent/attach` package (`Manager` interface, `TCManager` clsact/tc
  lifecycle) is the pattern to mirror — add a sibling, do not refactor `TCManager`.

Acceptance Criteria:
1. New attach manager (`cgroup_linux.go` + `sockmap_linux.go`) loads the SockOps
   and SkMsg objects with maps pinned under the agent pin dir (so `sockhash` /
   `identity_map` / `policy_map` / `metrics_map` are the SAME instances the TC
   datapath uses), then:
   - attaches `sock_ops` to the cgroup v2 path via `BPF_CGROUP_SOCK_OPS`
     (`link.AttachCgroup`), and
   - attaches `sk_msg` to `sockhash.FD()` via `BPF_SK_MSG_VERDICT`
     (`link.RawAttachProgram`).
2. `EnsureAttached` is idempotent (re-running neither errors nor double-attaches);
   `Detach` cleanly removes both attachments (`link.Close` / `RawDetachProgram`).
3. `cmd/meridian-agent/main.go` gains a `--cgroup` flag; when set, the agent
   attaches the SOCKMAP programs after the existing TC ingress/egress attach.
   Absent `--cgroup`, SOCKMAP attach is skipped — **no behavior change** for
   current TC-only deployments.
4. T3 smoke (root, Linux): agent (or the manager directly) attaches with a real
   cgroup v2 path + pinned `sockhash`; `sock_ops` and `sk_msg` are enumerable
   (`bpftool prog show` or the cilium/ebpf info API); `EnsureAttached` twice is a
   no-op; `Detach` removes both. Reuse `harness.RequireRoot` / `PinDir` /
   `currentCgroupV2Path` conventions.
5. ARCHITECTURE decision-log entry recorded at the next free number **D20**
   (D19 is already taken by the MER-48 helper-boundary decision — do NOT reuse it)
   for the agent SOCKMAP attach path.
6. No regression: `go build ./...` clean; `make test-bpf`, `make test-integration`,
   `make check-gate-skips` (0 skips / 0 failures across all 7 armed gates) stay
   green; `make ebpf` leaves the tree clean (this ticket changes agent Go + docs
   only — NO `bpf/*.c`/`.o` change).
7. After commit, `git status` is clean and `make check-commits` passes (MER-57 ref).

Files Expected To Change:
- internal/agent/attach/cgroup_linux.go    (new — sock_ops → cgroup v2 attach manager)
- internal/agent/attach/sockmap_linux.go   (new — sk_msg → sockhash BPF_SK_MSG_VERDICT attach)
- internal/agent/attach/cgroup_test.go     (new — T3 idempotent attach/detach + enumeration smoke)
- cmd/meridian-agent/main.go               (--cgroup flag; wire SOCKMAP attach after TC attach)
- docs/ARCHITECTURE.md                      (D20 decision-log entry)

Required Tests:
- T3 smoke               → attach idempotent, both programs enumerated, Detach removes them
- `go build ./...`       → agent builds with the new flag/manager
- `make test-bpf`        → P1.1 + MER-48/49/50 still green (no regression)
- `make test-integration`→ Phase-1 integration gates still green
- `make check-gate-skips`→ 0 skips, 0 failures across all 7 armed gates
- `make check-commits`   → MER-57 commit-linkage satisfied

Commit Message:
feat(agent): MER-57 cgroup sock_ops + sockhash sk_msg attach path
