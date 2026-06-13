# ADR-0001: Unknown Identity Posture

- **Status:** Accepted (Phase 1 contract freeze)
- **Date:** 2026-06-13
- **Relates to:** ARCHITECTURE D16 (`runtime_config_map` flag bits), D15
  (schema-mismatch fail-closed), the "still open: unknown-identity posture"
  item in ARCHITECTURE §Phase 0; MER-16 (`tc_ingress`), MER-17 (policy
  evaluation), MER-22 (reference evaluator).

## Context

Meridian resolves every IPv4 flow to a `{src_id, dst_id}` workload-identity
pair before any policy lookup. Identity `0` (`wire.IdentityUnknown`) is the
reserved "not in `identity_map`" value: it is what the datapath sees when a
source or destination IP has no identity mapping, when the agent has not yet
populated `identity_map`, or when L3/L4 parsing fails before an identity can
even be derived.

Two independent implementations — the kernel datapath (`bpf/tc_ingress.c`)
and the pure-Go source-of-truth evaluator (`internal/reference/evaluator.go`)
— were written against the same informal expectation and **converged on an
identical model**:

- Unknown / unresolvable identities collapse to `ID = 0`.
- The default verdict for a flow touching `ID = 0` is **deny**.
- A single runtime flag, `MERIDIAN_CFG_FALLOPEN_UNKNOWN`
  (`runtime_config_map[0]`, bit 0), flips that flow class to **allow**.

This convergence is currently a coincidence of two code paths, not a frozen
contract. Because the kernel verdict and the reference verdict are checked
for bit-exact equivalence (the compiler ≡ reference harness), any future
drift in this posture — e.g. one path treating a parse failure as implicit
allow while the other denies — is exactly the silent-divergence class the
reference evaluator exists to catch. The posture must be pinned before
Phase 1 policy evaluation (MER-17) and downstream consumers build on it.

## Problem Statement

When a flow cannot be tied to two known identities, the datapath has no rule
to match and must still return a single, well-defined verdict. The open
question (flagged in the architecture's Phase 0 review) is **which default**:

- **Fail-open** (passthrough) — unknown flows are allowed; safer for
  availability during identity-map warmup and bootstrap, weaker security.
- **Fail-closed** (default-deny) — unknown flows are dropped; stronger
  security, but a cold or stale `identity_map` can black-hole legitimate
  traffic.

The decision must also fix:

1. The exact trigger surface — what counts as "unknown" (missing mapping,
   identity value `0`, and pre-identity parse failure).
2. The override mechanism and its default state.
3. That the kernel and reference paths share one posture, byte-for-byte.

## Decision

The unknown-identity posture is **frozen** as follows.

**Default: DENY unknown identities.**

A flow whose source or destination identity is unknown is denied. In the
datapath this is `TC_ACT_SHOT`; in the reference evaluator it is
`wire.PolicyActionDeny`. "Unknown" is defined to include all of:

- the IP has no entry in `identity_map` (lookup miss), or
- the looked-up identity value is `0` (`wire.IdentityUnknown`), or
- L3/L4 parsing failed before an identity could be derived — a parse failure
  is treated as unknown-identity posture, **not** as implicit allow.

The unknown-identity check runs **before** the policy-rule lookup, so it can
never fall through to a rule match. Correspondingly, **rules may not
reference identity `0`** — the reference evaluator rejects any such rule at
construction (`validateRule`), so unknown is purely a posture, never a
matchable key.

**Optional: ALLOW unknown identities when `MERIDIAN_CFG_FALLOPEN_UNKNOWN`
is enabled.**

When bit 0 of `runtime_config_map[0]` is set, the same flow class returns
allow (`TC_ACT_OK` / `wire.PolicyActionAllow`). The flag is an **explicit
operator opt-in**; its unset/absent state — including a missing
`runtime_config_map` slot in the kernel — resolves to fail-closed. The flag
toggles only the unknown-identity class; it does not affect verdicts for
flows between two known identities.

Both implementations MUST produce the same verdict for the same flow under
the same flag state. This equivalence is a freeze property, not an
implementation detail.

## Alternatives Considered

1. **Fail-open by default, fail-closed as the opt-in.** Rejected: makes the
   safe-by-default posture the one an operator has to remember to turn on.
   A misconfigured, forgotten, or zeroed `runtime_config_map` would silently
   allow all unidentified traffic — the worst failure mode for a policy
   enforcement point. The chosen default ensures absence-of-config means
   absence-of-trust.

2. **No toggle — fail-closed always.** Rejected: identity-map warmup,
   bootstrap, and incident debugging need a documented escape hatch. Without
   one, operators would reach for cruder, less reversible measures (detaching
   the TC program, wiping policy) that lose all enforcement rather than just
   the unknown-flow class. One auditable runtime bit is safer than that.

3. **Per-identity or per-CIDR posture (allow unknown only for selected
   ranges).** Rejected as out of scope for the freeze: it reintroduces a
   matchable notion of "unknown," contradicting "rules must not reference
   identity 0," and adds hot-path lookups. If selective treatment is ever
   needed it is a real identity mapping (assign the range an identity), not a
   posture knob.

4. **Treat L3/L4 parse failure as a separate (allow) class from
   unresolved identity.** Rejected: it creates two posture surfaces that can
   drift, and an attacker-malformed packet that defeats parsing would bypass
   enforcement. Folding parse failure into the unknown-identity posture keeps
   one decision point and one flag.

5. **Compile-time / load-time constant instead of a runtime map flag.**
   Rejected: changing posture would require recompiling and reattaching the
   BPF programs, breaking the chaos requirement that enforcement survive
   agent restarts. A `runtime_config_map` bit is changeable live by the agent
   with no datapath teardown.

## Security Implications

- **Default is deny-by-omission.** Any path that fails to configure the flag
  — fresh install, zeroed map, missing slot — yields fail-closed. There is no
  configuration state in which forgetting to act results in allowing unknown
  traffic.
- **Parse failure cannot bypass policy.** Malformed or truncated packets that
  defeat L3/L4 parsing are denied under the default, closing a parser-evasion
  bypass.
- **`MERIDIAN_CFG_FALLOPEN_UNKNOWN` is a security-relevant control.** Enabling
  it allows all flows that touch an unresolved identity and SHOULD be treated
  as a privileged, audited, time-boxed action (e.g. bootstrap/debug only).
  Operationally it should raise an alert while set; leaving it on in steady
  state defeats identity-based enforcement.
- **Unknown is never matchable.** Because identity `0` cannot appear in a
  rule, an attacker cannot craft a flow that both reads as "unknown" and
  matches a permissive rule — the posture is decided strictly before rule
  evaluation.

## Operational Implications

- **Cold-start / warmup is the main hazard of the default.** Until the agent
  has populated `identity_map`, flows resolve to unknown and are dropped. The
  architecture's mitigation stands: the agent SHOULD populate `identity_map`
  **before** TC attach so steady state never sees a cold map. Where a warmup
  gap is unavoidable, `MERIDIAN_CFG_FALLOPEN_UNKNOWN` is the documented,
  reversible bridge.
- **The flag is live-flippable.** The agent writes `runtime_config_map[0]`;
  programs read it per-packet. No reattach, no policy reload, no dropped
  connections from toggling posture.
- **Degraded-mode behavior is unchanged.** Control-plane-unreachable mode
  enforces last-known-good kernel state; this ADR does not alter that — the
  unknown posture is whatever the last-written flag state was.
- **Observability:** denied unknown flows surface through the standard
  deny path (`denied_flows_map` + event in MER-17). Operators diagnosing
  "traffic black-holed after deploy" should first check `identity_map`
  population and the `FALLOPEN_UNKNOWN` bit.

## Testing Requirements

1. **Kernel ⇄ reference equivalence (mandatory).** The compiler ≡ reference
   harness MUST assert bit-exact verdict agreement between `tc_ingress` and
   `MapEvaluator` across the unknown-identity matrix:
   {src unknown, dst unknown, both unknown, both known} × {flag set,
   flag unset}. Drift here is a release blocker.
2. **Default fail-closed.** With `runtime_config_map` unset/absent, every
   unknown-identity flow returns deny (`TC_ACT_SHOT` / `PolicyActionDeny`).
   Explicitly cover the missing-map-slot case in the kernel path.
3. **Opt-in fail-open.** With bit 0 set, the same flows return allow; flows
   between two known identities are unaffected by the flag.
4. **Parse-failure posture.** Truncated / malformed Ethernet, IPv4, and
   TCP/UDP frames follow the unknown-identity posture (deny by default,
   allow under the flag) — never implicit allow under the default.
5. **Rule-validation guard.** `NewEvaluator` MUST reject any rule whose src
   or dst identity is `0`, preventing "unknown" from becoming matchable.
6. **Resolution order.** A flow with an unknown identity that *would* match a
   permissive rule if the rule were consulted MUST still be decided by the
   posture (deny by default), proving the unknown check precedes rule lookup.
7. **Go suite hygiene:** table-driven tests, `go test -race ./...`, coverage
   ≥ 80% on `internal/reference`.
