# Active Ticket

ID: MER-50

Title: sk_msg.c — SOCKHASH redirect + SK_PASS fall-through + redirect telemetry

Objective:
Fill the MER-47 `sk_msg` skeleton with the intra-node redirect fast path. On
`sendmsg`, look up the destination peer socket in `sockhash` by `sock_key` and,
on hit, redirect the message to that peer; on miss, return `SK_PASS` so the
normal kernel TCP path is unchanged (ADR-0007 fall-through contract). This is the
SOCKHASH *consumer* — safe to land now that the P2.1-N gate (MER-49) guarantees
only `ALLOW + SOCKMAP_ELIGIBLE` sockets are ever in `sockhash`, so a hit can never
redirect a flow that required mTLS / L7 / proxy / deny handling.

`sk_msg` is the SOLE reader of `sockhash` and never inserts, repairs, or broadens
it — write authority stays in `sock_ops` (MER-48). Do NOT modify `sock_ops.c` or
any frozen schema. The byte-level integrity + denied-never-redirected integration
proof is the separate gate MER-51 — do not fold it in here.

Dependencies:
- MER-48 (DONE `77540ce`): `sockhash` populated by gated `sock_ops`;
  `meridian_helpers.h` available.
- MER-49 (DONE `d0125c1`): P2.1-N armed gate locks the CC-5 insertion invariant —
  the precondition that makes consuming `sockhash` safe.
- ADR-0007 (§"sk_msg redirect contract"): hit → redirect; miss → `SK_PASS`;
  never write `sockhash`. ARCHITECTURE D13 (decision-point emission, bounded —
  NOT per-message). ADR-0004 (frozen schema: `sock_key`/`sockhash` unchanged).

Acceptance Criteria:
1. On each `sendmsg`, `meridian_sk_msg` builds the destination `sock_key`
   { dst_ip = msg->remote_ip4 (network order), dst_port = msg->remote_port
   (NETWORK order in sk_msg_md — convert as needed), pad = 0 } and looks it up
   in `sockhash`.
2. On HIT: redirect to the peer socket via **`bpf_msg_redirect_hash`** (the
   SOCKHASH helper — NOT `bpf_msg_redirect_map`, which is index-based SOCKMAP)
   with `BPF_F_INGRESS` so the peer receives on its ingress queue; the program
   returns the helper's verdict. On MISS: return `SK_PASS` (normal kernel path).
   `sk_msg` has no `SK_REDIRECT` action — the verdict is the helper's result.
3. Redirect telemetry: increment a redirect counter (`METRIC_FLOWS_REDIRECTED`
   or a reserved sockmap slot from `metric_id` 8..15) on the hit path, and
   populate `flow_event.latency_ns` per D13. Emission MUST stay decision-point
   bounded — do NOT emit a ring event on every `sendmsg` (that would be
   per-message; bound it, e.g. first redirect per flow, or counter-only with
   latency on a bounded event). State the chosen bound in a code comment.
4. Loads **verifier-clean** on 5.15 (null-check the sockhash lookup; no unbounded
   loops). The miss path must not touch `sockhash` or counters beyond the contract.
5. T2/T3 smoke (prog_test_run is NOT supported for SK_MSG on 5.15 — use real
   attach): attach `sk_msg` with `BPF_SK_MSG_VERDICT` to `sockhash` and `sock_ops`
   to the cgroup, establish an eligible loopback flow (reuse the MER-48/49
   harness), send bytes, and prove the redirect path ran (peer receives AND/OR
   the redirect counter increments). A non-eligible flow (absent from sockhash)
   sends bytes that arrive via the normal path with the redirect counter
   unchanged (SK_PASS fall-through).
6. `make ebpf` regenerates `skmsg_bpfel.{o,go}` (byte-identical on re-run); if
   `meridian_consts.h` is touched (shared header), the consequent counter/tc*
   object regenerations are committed (no stale drift).
7. No regression: `make test-bpf`, `make test-integration`, `make
   check-gate-skips` (0 skips / 0 failures across all 7 armed gates) stay green;
   `git status` clean; `make check-commits` passes (MER-50 ref).

Files Expected To Change:
- bpf/sk_msg.c                       (redirect + fall-through + telemetry)
- bpf/include/meridian_consts.h      (only if a dedicated redirect metric/mark const is added — shared header)
- bpf/skmsg_bpfel.o / .go            (regenerated binding; + any objects forced by a consts.h change)
- test/bpf/skmsg_test.go             (new — T2/T3 redirect-hit + miss-fallthrough smoke)

Required Tests:
- `make ebpf`             → sk_msg compiles + loads verifier-clean; bindings byte-identical on re-run
- `make test-bpf`         → new sk_msg smoke green + P1.1 matrix + P2.1-N gate still green
- `make test-integration` → Phase-1 integration gates still green
- `make check-gate-skips` → 0 skips, 0 failures across all 7 armed gates
- `make check-commits`    → MER-50 commit-linkage satisfied

Commit Message:
feat(ebpf): MER-50 sk_msg SOCKHASH redirect + SK_PASS fall-through (ADR-0007)
