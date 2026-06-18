# Active Ticket

ID: MER-77

Title: Revise ADR-0008 — CC-2 resource encoding without a protoc toolchain dependency

Objective:
ADR-0008 §2 (MER-70) froze the CC-2 resource payload as protoc-generated
`meridian.config.v1` messages — but the build environment has **no protoc**
(`protoc`/`protoc-gen-go`/`buf` absent on the host AND the Lima 5.15 VM; protoc is
not a `go install` tool), and a protoc build dependency cuts against D11 (minimal
deps, none ahead of need). MER-72 (A-3, the Phase-3 critical path) is blocked on
this. Revise ADR-0008 to specify a **no-protoc, deterministic, versioned** wire
encoding that meets the CC-2 goals — frozen field set, schema-versioned,
evolvable, decodable, superseding the opaque interim blob — without codegen.
Pure-docs ADR amendment; no code (MER-72 implements against the revised ADR).

Stay in scope: the ADR-0008 amendment + the matching ARCHITECTURE D22 update. Do
NOT implement the encoding or the agent client (that is the re-scoped MER-72), and
do NOT change the §1 type_url mapping or §3 commit-ordering decisions.

Dependencies:
- Amends ADR-0008 (MER-70 `0054b5f`). No protoc. No other dependency.
- Unblocks MER-72 (A-3). The §1 (CDS=policy/EDS=identity) and §3 (identity→policy
  commit ordering, ACK-after-commit, never transiently widen) decisions stand.

Acceptance Criteria:
1. ADR-0008 §2 revised: replace the protoc proto schema with a **no-protoc
   encoding spec** for the resource `Any` payload — a frozen, versioned,
   field-stable representation of `wire.PolicyRule` / `wire.Identity` (either a
   documented JSON schema decoded with `DisallowUnknownFields` + explicit integer
   widths + a `schema_version` field, OR a hand-rolled fixed-layout binary codec
   mirroring the ADR-0004 kernel structs). Field contract + evolution rules
   (additive only; reject unknown/over-range → NACK) frozen.
2. Record **why** (no protoc toolchain in host/Lima/CI; D11 minimal-deps) and that
   this supersedes the interim encoding by **freezing + versioning** it, not by
   adding codegen. The decision is reversible if protoc is later provisioned (note
   that explicitly).
3. ADR-0008 header carries a `Revised: <date> (MER-77)` line (Status stays
   Accepted); ARCHITECTURE **D22** updated to describe the no-protoc encoding;
   ADR index note unchanged (still 0008, no new number).
4. No production code; `go build ./...` unaffected; `make check-commits` passes
   (MER-77 ref); `git status` clean after commit.

Files Expected To Change:
- docs/adr/0008-xds-wire-contract.md   (§2 encoding spec → no-protoc; header Revised line)
- docs/ARCHITECTURE.md                 (D22 → no-protoc encoding)

Required Tests:
- `make check-commits`   → MER-77 commit-linkage satisfied
- `go build ./...`       → unaffected (docs-only)
- the revised §2 is concrete enough for MER-72 to implement with the stdlib +
  existing deps only (no protoc)

Commit Message:
docs(adr): MER-77 revise ADR-0008 CC-2 encoding — no protoc dependency (versioned codec)
