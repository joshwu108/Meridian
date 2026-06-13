# ADR-0004: Map-schema freeze (v2 maps + cross-boundary structs)

- **Status:** Reserved — not yet written (Phase-1 exit gate; authored by MER-34)
- **Date:** 2026-06-13 (reservation only)
- **Relates to:** ROADMAP [CC-2](../../ROADMAP.md#cross-cutting-decisions)
  (compiled-policy wire contract), ARCHITECTURE D12–D17, MER-34 (Phase-1 exit
  gate). Consumed by every subsystem that reads or writes pinned maps after
  Phase 1.
- **Tracking ticket:** MER-34
- **Provenance:** Number `0004` reserved by **MER-41** to close the ADR index
  gap after ADR-0005 was authored ad hoc inside the MER-26 commit (`754e2ee`)
  with no registry row, and ADR-0006 (MER-40) widened the sequence. No other ADR
  may claim this number; the full decision document will be written when MER-34
  closes the five upstream gates.

## Reserved scope (MER-34 will author)

This stub records the **allocation only**. MER-34 will freeze:

- Every v2 BPF map schema in `meridian_maps.h`
- Every cross-boundary struct in `meridian_types.h` (kernel half of CC-2)
- The `MERIDIAN_SCHEMA_VERSION` bump procedure
- D12–D17 outcomes as-built in `docs/ARCHITECTURE.md` (deviations noted, not
  papered over)

Do not expand this file until MER-34 is green on gates MER-18, MER-21, MER-24,
MER-29, and MER-32. See [`docs/adr/README.md`](README.md) for the authoritative
ADR registry and next-free number (`0007`).
