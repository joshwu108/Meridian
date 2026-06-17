# Active Ticket

ID: MER-67

Title: ARCHITECTURE D21 — record the ADS server decision + flag interim xDS encoding (CC-2-pending)

Objective:
Formalize the Phase-2 ADS server (MER-54/55/56) as a numbered decision-log entry
(**D21**) in `docs/ARCHITECTURE.md`. The decision is architecturally significant —
it added the gRPC + `go-control-plane` dependency, the per-(stream, type_url)
version/nonce state machine, the `Store.Watch()`-driven ordered push, and a **new
cross-boundary xDS resource encoding** — yet the decision log stops at D20 and the
encoding lives only in code comments + the prose "Pending — D21" pointer MER-59
(`d8c7612`) added. The project deliberately defers the real CC-2 compiled-policy
wire contract to Phase 3, so the interim encoding must be **explicitly tracked as a
placeholder**, not left implicit. Pure-docs — no Lima, no production code.

Stay in scope: `docs/ARCHITECTURE.md` only (the D21 decision-log entry + reconcile
the existing prose pointer). Do NOT change production code, the frozen ADR-0004
schema, or start MER-58 / Phase-3 work. Do NOT author a separate ADR file (D21 is a
decision-log row; the CC-2 wire-contract ADR is a distinct Phase-3 deliverable).

Dependencies:
- MER-54 (ADS server) CLOSED `0ff966d`, MER-55 `fe453b5`, MER-56 `2898a75` — the
  as-built behavior D21 records. Coordinates with the deferred CC-2 wire-contract
  ADR (Phase-3) — D21 explicitly marks the interim encoding as superseded by it.
- Off critical path (P3/LOW); blocks nothing. Phase 2 is already complete (MER-59
  `d8c7612` + MER-68 `1b5bdf3`).

Acceptance Criteria:
1. `docs/ARCHITECTURE.md` gains a **D21** entry in the decision-log **table** (the
   D1…D20 table) recording, as-built: the ADS server package
   (`internal/control/ads`); the gRPC + `go-control-plane` dependency addition
   (per D11 — deps recorded by the phase that first imports them); the
   per-(stream, type_url) version/nonce protocol (ACK advances accepted version,
   NACK holds last-known-good per CC-5, stale nonce ignored); the `Store.Watch()`-
   driven CDS→EDS / LDS→RDS ordered push; and the **interim** resource encoding
   (JSON `[]wire.PolicyRule` in a `wrapperspb.BytesValue` Any on the Cluster
   channel only; other channels versioned-but-empty) with an explicit "**superseded
   by the CC-2 wire-contract freeze (Phase-3)**" caveat.
2. The existing prose "**Pending — D21 (ADS server, tracked by MER-67)**" pointer
   is reconciled — updated to reference the now-formal D21 entry (no longer
   "pending"/"not yet a numbered entry"), so there is one source of truth.
3. The entry cross-references the relevant ARCHITECTURE CC-2 / xDS text and ROADMAP
   CC-2, so the interim-vs-frozen boundary is unambiguous.
4. No production code changes; `go build ./...` / `go vet ./...` unaffected;
   `make check-commits` passes (MER-67 ref); `git status` clean after commit.

Files Expected To Change:
- docs/ARCHITECTURE.md     (add D21 decision-log row; reconcile the prose pointer)

Required Tests:
- `go build ./...` / `go vet ./...` → unaffected (docs-only)
- `make check-commits`             → MER-67 commit-linkage satisfied
- visual: D21 row present in the decision-log table; prose pointer reconciled; CC-2 cross-reference present

Commit Message:
docs(arch): MER-67 record ADS server decision D21 — interim xDS encoding CC-2-pending
