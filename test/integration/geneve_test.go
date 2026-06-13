//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	identityRemoteClient = wire.IdentityID(1001)
	identityLocalServer  = wire.IdentityID(2001)
	geneveAllowPort      = 18080
	geneveDenyPort       = 18081
)

// TestGeneveIngressIdentityPolicyGate_MER21 is the P1.3 gate: cross-node traffic
// carries remote src_identity in the Geneve TLV (MER-20 egress stamp), node B's
// tc_ingress decodes it (MER-21), and policy keyed on that identity enforces
// allow and deny cases on the two-node harness (MER-28).
func TestGeneveIngressIdentityPolicyGate_MER21(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	top := harness.NewTwoNode(t, "geneve-gate", 80)
	pinDir := harness.PinDir(t)

	ingressObjs, egressObjs, writer := loadGenevePrograms(t, pinDir)
	t.Cleanup(func() {
		_ = ingressObjs.Close()
		_ = egressObjs.Close()
	})

	ingressPin := filepath.Join(pinDir, "tc_ingress_prog")
	egressPin := filepath.Join(pinDir, "tc_egress_prog")
	if err := ingressObjs.MeridianTcIngress.Pin(ingressPin); err != nil {
		t.Fatalf("pin tc_ingress: %v", err)
	}
	if err := egressObjs.MeridianTcEgress.Pin(egressPin); err != nil {
		t.Fatalf("pin tc_egress: %v", err)
	}

	harness.AttachTCEgress(t, top.NodeA.Namespace, top.NodeA.Veth, egressPin)
	harness.AttachTCIngress(t, top.NodeB.Namespace, top.NodeB.Veth, ingressPin)

	ctx := context.Background()

	// Node A needs a local identity mapping so tc_egress can stamp the TLV.
	if err := harness.SeedIdentity(ctx, writer, wire.Identity{
		ID:       identityRemoteClient,
		PodIPv4:  top.NodeA.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/remote-client",
	}); err != nil {
		t.Fatalf("seed node A identity: %v", err)
	}
	// Node B resolves the destination locally; remote src is carried only in Geneve.
	if err := harness.SeedIdentity(ctx, writer, wire.Identity{
		ID:       identityLocalServer,
		PodIPv4:  top.NodeB.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/local-server",
	}); err != nil {
		t.Fatalf("seed node B identity: %v", err)
	}

	if err := harness.SeedPolicy(ctx, writer, wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: identityRemoteClient,
			DstIdentity: identityLocalServer,
			DstPort:     geneveAllowPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}); err != nil {
		t.Fatalf("seed allow policy: %v", err)
	}
	if err := harness.SeedPolicy(ctx, writer, wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: identityRemoteClient,
			DstIdentity: identityLocalServer,
			DstPort:     geneveDenyPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}); err != nil {
		t.Fatalf("seed deny policy: %v", err)
	}

	harness.AssertAllowed(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveAllowPort)
	harness.AssertDenied(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveDenyPort)
}

func loadGenevePrograms(t *testing.T, pinDir string) (*bpf.TcIngressObjects, *bpf.TcEgressObjects, datapath.Writer) {
	t.Helper()

	// Open pinned maps via the counter loader (schema sentinel + shared maps).
	counter, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("load shared counter/maps: %v", err)
	}
	if err := counter.Close(); err != nil {
		t.Fatalf("close counter after map pin: %v", err)
	}

	var ingress bpf.TcIngressObjects
	if err := bpf.LoadTcIngressObjects(&ingress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		t.Fatalf("load tc_ingress: %v", err)
	}

	var egress bpf.TcEgressObjects
	if err := bpf.LoadTcEgressObjects(&egress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		_ = ingress.Close()
		t.Fatalf("load tc_egress: %v", err)
	}

	writer := datapath.NewWriter(ingress.IdentityMap, ingress.PolicyMap)
	return &ingress, &egress, writer
}
