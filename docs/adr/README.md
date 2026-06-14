# Architecture Decision Records

This directory holds Meridian's Architecture Decision Records (ADRs). Each ADR
freezes one cross-cutting decision (a contract, a posture, a layout) before the
code that depends on it is written, and records the rejected alternatives so the
decision is not silently relitigated.

This index is the **authoritative ADR registry**. Every ADR — including any
authored ad hoc inside a feature commit — MUST appear in the table below with an
owning ticket and a status, so an orphaned/untracked ADR (the MER-41 trigger) is
caught at review instead of discovered later.

## Index

| ADR | Title | Owning ticket | Status | Notes |
|-----|-------|---------------|--------|-------|
| [0001](0001-unknown-identity-posture.md) | Unknown-identity posture (default-deny + `FALLOPEN_UNKNOWN`) | **MER-11** | Accepted | Phase 1 contract freeze. |
| [0002](0002-geneve-topology.md) | Geneve topology — attachment point, tunnel ownership, node fabric | **MER-12** (authored); frozen with **MER-28** | Accepted | Planned filename was `0002-geneve-parse-placement.md`; renamed to `0002-geneve-topology.md` when the decision widened beyond parse placement. |
| [0003](0003-policy-key.md) | `policy_key` carries an explicit direction byte | **MER-14** | Accepted | Schema v2 contract freeze (ADR/D12). |
| [0004](0004-map-schema-freeze.md) | Map-schema freeze (v2 maps + cross-boundary structs) | **MER-34** | Accepted | Phase-1 exit gate; kernel half of CC-2. D12–D17 as-built in ARCHITECTURE. |
| [0005](0005-geneve-encap-failure-policy.md) | Geneve encapsulation failure policy (drop vs pass-unencapsulated) | **MER-41** (tracking; backfilled) | Accepted | Authored ad hoc inside the MER-26 commit (`754e2ee`) with no tracking ticket; linkage backfilled by MER-41. Resolves the encap-failure item deferred by ADR-0002. Consumed by MER-20/21/28/29. |
| [0006](0006-original-destination-recovery.md) | Original-destination recovery (CC-1) — TPROXY vs eBPF DNAT | **MER-40** | Accepted | Phase-4 **entry gate**; formalizes ARCHITECTURE D1 (TPROXY + `IP_TRANSPARENT`, no orig-dst map in v1). Validated by the node-proxy P4.1 no-TLS echo prototype before Phase 4 starts. Consumed by A-5 + P4.1–4.4. |

**Next free ADR number: `0007`.** `0004` is *accepted* (MER-34);
`0005` and `0006` are *used*.

## Conventions

1. **Filename:** `NNNN-kebab-case-title.md`, zero-padded four-digit sequence
   starting at `0001`. Numbers are allocated from this index — claim the
   "next free" number above and update it in the same change.
2. **Reserved numbers count as allocated.** A number reserved for an in-flight
   ticket (e.g. `0004` → MER-34) is not free; do not reuse it. This is what the
   `0004` gap is: a hole reserved for MER-34, not an error.
3. **Every ADR has an owning ticket and a row here.** An ADR committed without a
   MER reference (as `0005` was) must be backfilled into this table with its
   tracking ticket and a one-line provenance note in the ADR header. New ADRs
   add their row in the authoring commit.
4. **Header block:** each ADR starts with `Status`, `Date`, and `Relates to`;
   ad-hoc/backfilled ADRs additionally carry `Tracking ticket` and `Provenance`.
5. **Status values:** `Proposed`, `Accepted`, `Superseded by ADR-XXXX`,
   `Reserved — not yet written` (a claimed-but-unwritten slot).
