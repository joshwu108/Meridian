# MER-28 Two-Node Integration Harness

Phase 1 integration topology used by Geneve and policy integration tests.

## Topology Diagram

```text
root netns
  172.31.N.1/30 (HostVethA) ───── 172.31.N.2/30 (NodeA underlay)
  172.31.N+1.1/30 (HostVethB) ─── 172.31.N+1.2/30 (NodeB underlay)
                         route via root                  route via root
node-a ns ------------------------------------------------------------- node-b ns
    gnv0: 10.200.N.1/24 <======= Geneve VNI 100 / UDP 6081 =======> gnv0: 10.200.N.2/24
```

## What The Harness Provides

- `NewTwoNode(t, name, baseOctet)`:
  - creates two netns virtual nodes
  - creates two underlay veth pairs
  - configures node-to-node routing through root netns
  - creates the Geneve tunnel + overlay addresses
  - registers automatic cleanup via `t.Cleanup`
- `SeedIdentity(ctx, writer, identity)` and `SeedPolicy(ctx, writer, rule)`:
  - seed helpers that only call `datapath.Writer.Apply`
  - no direct map mutations
- `AssertAllowed(...)` and `AssertDenied(...)`:
  - `nc`-based connection assertions
  - readiness + assertions use `WaitUntil` (no sleep-based waits)
  - note: current deny example is routing-denied; policy-deny assertions land with
    the policy integration tests

## Integration Usage Examples

```go
func TestPolicyPath(t *testing.T) {
    harness.RequireRoot(t)
    top := harness.NewTwoNode(t, "p1", 80)

    // Seed desired datapath state only via datapath.Writer.
    if err := harness.SeedIdentity(ctx, writer, wire.Identity{
        ID: 101, SpiffeID: "spiffe://cluster.local/ns/default/sa/frontend",
    }); err != nil {
        t.Fatal(err)
    }
    if err := harness.SeedPolicy(ctx, writer, wire.PolicyRule{
        Key: wire.PolicyRuleKey{SrcIdentity: 101, DstIdentity: 202, DstPort: 8080, Protocol: 6},
        Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
    }); err != nil {
        t.Fatal(err)
    }

    harness.AssertAllowed(
        t,
        top.NodeA.Namespace,
        top.NodeB.Namespace,
        top.NodeB.OverlayIP,
        8080,
    )
}
```

```go
func TestDenyPath(t *testing.T) {
    harness.RequireRoot(t)
    top := harness.NewTwoNode(t, "deny", 81)

    harness.AssertDenied(
        t,
        top.NodeA.Namespace,
        top.NodeB.Namespace,
        top.NodeB.OverlayIP,
        8080,
    )
}
```
