# Active Ticket

ID: MER-47

Title: Phase 2 contract land — SOCKHASH map + sock_ops/sk_msg skeletons (Wave 0)

Objective:
Land the Phase-2 datapath contract so every downstream SOCKMAP ticket has a
stable surface to compile against. This is the Wave-0 serialization point: the
entire eBPF lane (MER-48/49/50/51/52) and Agent lane (MER-57/58) depend on it.
Define the pinned `sockhash` map and add verifier-clean **no-op/skeleton**
`sock_ops.c` and `sk_msg.c` programs (no redirect logic yet — that is MER-48/50),
wire them into the bpf2go generation, regenerate committed bindings, and record
the decision in the ARCHITECTURE log (D18). No policy/redirect behavior in this
ticket — contract and skeletons only.

Phase-2 entry gate is satisfied at HEAD 630f616: MER-34 (Phase-1 exit) is green —
all five gates pass with 0 skips and ADR-0004 is Accepted. Phase-2 tickets are
therefore mergeable.

Dependencies:
- Phase-2 entry: MER-34 green (SATISFIED at HEAD 630f616 — all five Phase-1 gates
  green, ADR-0004 Accepted, `make check-gate-skips` 0 skips).
- Binding contracts: ADR-0007 (SOCKMAP redirect architecture — SOCKHASH map shape,
  verdict-gated insertion, sk_msg redirect/fall-through contract) is the design
  this ticket lands the skeleton for; ADR-0004 (frozen Phase-1 map schema — must
  NOT be mutated; the sockhash is a new map, not a schema change to existing maps).
- `POLICY_FLAG_SOCKMAP_ELIGIBLE` (bit 0) already exists in
  `bpf/include/meridian_types.h` — do not redefine.

Acceptance Criteria:
1. `sockhash` map defined in `bpf/include/meridian_maps.h`:
   `BPF_MAP_TYPE_SOCKHASH`, `struct sock_key` key, value `__u64` (or per
   ADR-0007), pinned `LIBBPF_PIN_BY_NAME`. `struct sock_key` declared once in a
   C header (single-source per CC-6).
2. New `bpf/sock_ops.c` and `bpf/sk_msg.c` compile **verifier-clean** on 5.15 as
   no-op/skeleton programs (correct SEC() names, return pass/OK; no redirect or
   sock_hash_update logic yet).
3. Both programs are listed in `bpf/gen.go` with `sock_key` exported via `-type`;
   `make ebpf` regenerates the committed bpf2go bindings and the regenerated
   objects/bindings are byte-identical to source (no stale-object drift).
4. ARCHITECTURE decision-log entry **D18** recorded for the SOCKHASH map +
   sock_ops/sk_msg skeleton contract (log currently ends at D17).
5. No Phase-1 regression: `make test-bpf`, `make test-integration`, and
   `make check-gate-skips` (0 skips, 0 failures across all armed gates) stay green;
   ADR-0004-frozen maps are untouched.
6. After commit, `git status` is clean and `make check-commits` passes
   (conventional, MER-47-referenced commit per MER-45 linkage).

Files Expected To Change:
- bpf/include/meridian_maps.h        (sockhash map + struct sock_key)
- bpf/sock_ops.c                     (new — skeleton BPF_PROG_TYPE_SOCK_OPS)
- bpf/sk_msg.c                       (new — skeleton BPF_PROG_TYPE_SK_MSG)
- bpf/gen.go                         (add go:generate for both, -type sock_key)
- bpf/sockops_bpfel.o / .go          (new generated bindings)
- bpf/skmsg_bpfel.o / .go            (new generated bindings)
- docs/ARCHITECTURE.md               (D18 decision-log entry)

Required Tests:
- `make ebpf`            → sock_ops/sk_msg compile verifier-clean; bindings regenerate byte-identical
- `make test-bpf`        → Phase-1 bpf suite still green (no regression)
- `make test-integration`→ Phase-1 integration gates still green
- `make check-gate-skips`→ 0 skips, 0 failures across all armed Phase-1 rows
- `make check-commits`   → MER-47 commit-linkage satisfied

Commit Message:
feat(ebpf): MER-47 land Phase-2 contract — sockhash map + sock_ops/sk_msg skeletons
