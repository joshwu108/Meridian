# Active Ticket

ID: MER-48

Title: sock_ops.c — gated SOCKHASH population (P2.1 core, CC-5 insertion invariant)

Objective:
Fill the MER-47 `sock_ops` skeleton with the **policy-gated SOCKHASH insertion**
that is the heart of the Phase-2 intra-node fast path. On TCP established, the
program resolves the flow's compiled policy verdict and calls
`bpf_sock_hash_update()` into the shared `sockhash` map **only** when the verdict
is `ALLOW` carrying `POLICY_FLAG_SOCKMAP_ELIGIBLE`. Every other verdict class
leaves `sockhash` untouched. This map write is ROADMAP Top-risk #2 / eBPF R2 — the
exact point where a wrongly-inserted socket would later let `sk_msg` (MER-50)
silently bypass mTLS, L7 policy, redirect, or deny. The kernel re-checks the flag
at the write site even though the compiler is supposed to only ever set it for
plain-L4 allows (defense in depth, per ADR-0007).

This ticket lands the population + a **positive** smoke (eligible flow present
after connect). The exhaustive *negative* matrix (DENY / L7 / mTLS / REDIRECT /
ALLOW-without-flag all absent) is the **armed gate MER-49 (P2.1-N)**, which
depends on this ticket — do not fold MER-49's matrix in here.

Dependencies:
- MER-47 (DONE at `70c52ad`): `sockhash` map, `struct sock_key`, `sock_ops.c`
  skeleton (`SEC("sockops")` → `meridian_sock_ops`), and bpf2go bindings exist.
- Binding contracts:
  - ADR-0007 — gated-insertion invariant (§"Gated insertion invariant"): insert
    only on `ALLOW` + `POLICY_FLAG_SOCKMAP_ELIGIBLE`; the listed non-eligible
    classes (DENY, REDIRECT, ALLOW+`L7_REQUIRED`, ALLOW+`MTLS_REQUIRED`,
    ALLOW-without-flag, policy miss, malformed/unsupported) leave SOCKHASH untouched.
  - ADR-0004 — `sock_key` / `sockhash` / `policy_*` shapes are FROZEN; do not
    mutate them. `sock_key{dst_ip BE; dst_port BE; pad=0}`, value `__u64`.
  - ADR-0003 / D12 — `policy_key` carries an explicit `direction` byte
    (0=ingress, 1=egress); active vs passive established maps to the correct
    direction and src/dst-identity ordering.
  - CC-6 single-source: any reusable policy-resolution helper lives in a C header
    (`bpf/include/meridian_helpers.h`, new); do not duplicate the tc lookup logic.
- Blocks: MER-49 (P2.1-N gate), MER-50 (sk_msg redirect), MER-51/52, MER-57/58.

Acceptance Criteria:
1. `meridian_sock_ops` handles `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` and
   `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` (requesting them via
   `bpf_sock_ops_cb_flags_set` on the connect/established path as needed),
   resolves `(src_id, dst_id, dst_port, proto, direction)` from the socket
   4-tuple via `identity_map`, and looks up `policy_map`.
2. `bpf_sock_hash_update(ctx, &sockhash, &key, …)` is called **iff**
   `verdict.action == ALLOW && (verdict.flags & POLICY_FLAG_SOCKMAP_ELIGIBLE)`.
   The key is `sock_key{dst_ip, dst_port, pad=0}` in network order. ALL other
   verdict classes — and policy miss, malformed key material, or unsupported
   proto — return without touching `sockhash` (CC-5).
3. `sock_ops.c` loads **verifier-clean** on 5.15 (no unbounded loops, all map
   values bounds-checked before use).
4. T2 smoke (prog_test_run or cgroup attach) proves an eligible
   `ALLOW + SOCKMAP_ELIGIBLE` flow's socket **is present** in `sockhash` after
   connect; a single DENY (or non-eligible) control case proves **absence**.
   (Full negative matrix is MER-49, not here.)
5. `make ebpf` regenerates bindings **byte-identical** to source; ADR-0004 frozen
   maps and `sock_key`/`sockhash` shape are unchanged (no schema-contract drift).
6. No Phase-1 regression: `make test-bpf`, `make test-integration`, and
   `make check-gate-skips` (0 skips, 0 failures across all armed gates) stay green.
7. After commit, `git status` is clean and `make check-commits` passes
   (conventional, MER-48-referenced commit per MER-45 linkage).

Files Expected To Change:
- bpf/sock_ops.c                     (gated population: hook callbacks, policy resolve, sock_hash_update)
- bpf/include/meridian_helpers.h     (new — shared policy_key build + verdict lookup helper, CC-6)
- bpf/sockops_bpfel.o / .go          (regenerated bindings)
- test/bpf/sockops_test.go           (new — T2 positive smoke: eligible present, control absent)
- docs/ARCHITECTURE.md               (optional: D19 if the helper boundary warrants a decision-log note)

Required Tests:
- `make ebpf`             → sock_ops compiles verifier-clean; bindings regenerate byte-identical
- `make test-bpf`         → new sock_ops smoke green AND P1.1 verdict matrix still green (no regression)
- `make test-integration` → Phase-1 integration gates still green
- `make check-gate-skips` → 0 skips, 0 failures across all armed Phase-1 rows
- `make check-commits`    → MER-48 commit-linkage satisfied

Commit Message:
feat(ebpf): MER-48 sock_ops gated SOCKHASH population (CC-5 eligible-only insertion)
