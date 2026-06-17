# Active Ticket

ID: MER-70

Title: CC-2 ADR — compiled-policy + xDS resource wire contract (supersedes MER-54 interim encoding)

Objective:
Freeze the CC-2 cross-cutting decision the whole Phase-3 agent translation lane
(A-3 / MER-72) compiles against: the byte/message contract between control plane,
agent, and kernel for xDS resources. Today the MER-54 ADS server ships an
**interim** placeholder — a JSON-marshalled `[]wire.PolicyRule` packed in a
`wrapperspb.BytesValue` Any on the Cluster channel only (D21/MER-67). This ADR
records the real contract — which `type_url` carries which Meridian construct,
the resource message shape, and the write-ordering rules — and explicitly marks
the interim encoding as superseded. Pure docs/ADR; no code (the A-3 implementation
that adopts it is MER-72).

Stay in scope: the ADR + decision-log entry + ADR index. Do NOT change the MER-54
server encoding, the agent, or any code — MER-72 (A-3) implements against this
contract next. Do NOT start MER-71/72.

Dependencies:
- MER-54 (ADS server, interim encoding) `0ff966d`, D21/MER-67 `9d1790a` — the
  interim contract this supersedes. No other dependency (ADR is pure analysis).
- Soft prerequisite for MER-72 (A-3 translation) — should land before A-3
  completes so A-3 targets the frozen contract, not the placeholder.
- ROADMAP CC-2 ("freeze before Phase 3 completes"); ARCHITECTURE "xDS apply
  pipeline" + D17 (wire↔kernel translation boundary, the sole `datapath` writer).

Acceptance Criteria:
1. `docs/adr/0008-xds-wire-contract.md` (Status: Accepted) records:
   a. the `type_url`→Meridian mapping — CDS = compiled L4 policy / cluster, EDS =
      identity/endpoint metadata, LDS/RDS = L7 rules — with the rationale;
   b. the resource **message shape** for each channel (what proto/encoding carries
      `wire.PolicyRule` / `wire.Identity` / L7 rules), replacing the interim
      JSON-in-`BytesValue`-on-Cluster placeholder;
   c. the apply **write-ordering** contract (identities before referencing
      policies; remove-allow before add on shrink — never transiently widen);
   d. the **rejected alternatives** (e.g. keep JSON-in-BytesValue; custom non-xDS
      protocol) and why.
2. The ADR cross-references **D21 / MER-67** (interim encoding to be superseded)
   and the MER-72 (A-3) consumer; ARCHITECTURE decision log gains a one-line
   pointer entry (continue from D21).
3. `docs/adr/README.md` index updated; ADR numbering-gap check passes (0008 is
   the next free number).
4. No production code; `go build ./...` unaffected; `make check-commits` passes
   (MER-70 ref); `git status` clean after commit.

Files Expected To Change:
- docs/adr/0008-xds-wire-contract.md   (new — the CC-2 wire-contract ADR)
- docs/adr/README.md                   (index + numbering-gap entry)
- docs/ARCHITECTURE.md                 (one-line decision-log pointer to the ADR)

Required Tests:
- `make check-commits`   → MER-70 commit-linkage satisfied
- `go build ./...`       → unaffected (docs-only change)
- ADR index numbering-gap check passes; cross-refs to D21/MER-67/MER-72 resolve

Commit Message:
docs(adr): MER-70 ADR-0008 CC-2 xDS wire contract — supersede MER-54 interim encoding
