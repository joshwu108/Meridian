# MER-22 Edge Case Analysis

This document captures edge behavior for the reference evaluator implemented in
`internal/reference/evaluator.go`. It is intentionally narrow to the
`(src,dst,port,proto,direction) -> PolicyVerdict` oracle contract.

## Inputs and precedence

Evaluation order is deterministic:

1. Context validity (`nil` or canceled/deadline-exceeded)
2. Unknown-identity posture (`wire.IdentityUnknown` on either side)
3. Exact key match lookup
4. Default deny on miss

This order matters: unknown-identity posture is evaluated before map lookup, so
there is no path where unknown identities can match configured rules.

## Edge matrix

- `ctx == nil`
  - Behavior: error (`"nil context"`), no verdict returned.
  - Rationale: avoids panic on `ctx.Err()` and keeps evaluator failure explicit.
- `ctx.Err() != nil`
  - Behavior: propagates context error unchanged.
  - Rationale: caller controls cancellation/deadlines.
- `src == 0` or `dst == 0` with fail-open posture
  - Behavior: unconditional `ALLOW`.
  - Rationale: matches ADR-0001 fail-open mode.
- `src == 0` or `dst == 0` with fail-closed posture
  - Behavior: unconditional `DENY`.
  - Rationale: matches ADR-0001 fail-closed mode.
- Rule miss (identity/proto/port/direction mismatch)
  - Behavior: `DENY`.
  - Rationale: fail-closed default for non-matching traffic.
- Duplicate rule keys at construction
  - Behavior: constructor error.
  - Rationale: prevents nondeterministic "last write wins" ambiguity.

## Verdict validation edge cases

Rejected by `NewEvaluator`:

- Unknown action enum values.
- Unknown flag bits outside:
  - `SOCKMAP_ELIGIBLE`
  - `L7_REQUIRED`
  - `MTLS_REQUIRED`
  - `AUDIT`
- Sockmap invariant violations:
  - `SOCKMAP_ELIGIBLE` with non-`ALLOW` action.
  - `SOCKMAP_ELIGIBLE` + `L7_REQUIRED`.
  - `SOCKMAP_ELIGIBLE` + `MTLS_REQUIRED`.
- Unknown identities in rule definitions.
- Invalid direction byte (must be ingress/egress).

## Non-goals for MER-22

The evaluator does not:

- Interpret wildcard rules.
- Normalize protocol aliases.
- Mutate flags based on action.
- Resolve identity names.

Those concerns belong to compiler/control-plane layers and are verified against
this oracle in subsequent tickets.
