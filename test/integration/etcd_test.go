//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

// startEtcd launches a real etcd process on ephemeral loopback ports and
// returns its client endpoint. Skips the test when no etcd binary is in
// PATH so CI without etcd stays green. Unlike the netns tests in this
// package, this test needs neither Linux nor root.
func startEtcd(t *testing.T) string {
	t.Helper()
	etcdBin, err := exec.LookPath("etcd")
	if err != nil {
		t.Skip("etcd binary not in PATH; skipping etcd store integration test")
	}

	clientURL := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	peerURL := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, etcdBin,
		"--name", "meridian-test",
		"--data-dir", t.TempDir(),
		"--listen-client-urls", clientURL,
		"--advertise-client-urls", clientURL,
		"--listen-peer-urls", peerURL,
		"--initial-advertise-peer-urls", peerURL,
		"--initial-cluster", "meridian-test="+peerURL,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start etcd: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	waitForEndpoint(t, clientURL)
	return clientURL
}

// freePort reserves an ephemeral TCP port and releases it for etcd to bind.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForEndpoint polls until etcd accepts TCP connections (or times out).
func waitForEndpoint(t *testing.T, clientURL string) {
	t.Helper()
	addr := clientURL[len("http://"):]
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("etcd did not accept connections on %s within 30s", addr)
}

func testEtcdPolicyRule() wire.PolicyRule {
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: 101,
			DstIdentity: 202,
			DstPort:     8443,
			Protocol:    6, // TCP
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
}

// TestEtcdStoreIntegration exercises the etcd-backed store end to end
// against a real etcd process: policy put → Watch fires; identity put →
// retrievable; deletes propagate.
func TestEtcdStoreIntegration(t *testing.T) {
	endpoint := startEtcd(t)

	st, err := store.NewEtcd([]string{endpoint})
	if err != nil {
		t.Fatalf("connect etcd store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := st.Watch(ctx)

	// PUT a policy and verify Watch fires with a policy-changed event.
	rule := testEtcdPolicyRule()
	if err := st.PutPolicy(ctx, rule); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	waitForEvent(t, events, control.StoreEventPolicyChanged)

	rules, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(rules) != 1 || rules[0] != rule {
		t.Fatalf("policies = %+v, want exactly %+v", rules, rule)
	}

	// PUT an identity and verify it round-trips.
	ident := wire.Identity{
		ID:        101,
		PodIPv4:   "10.0.0.7",
		SpiffeID:  "spiffe://cluster.local/workload/payments/frontend",
		Namespace: "payments",
		Name:      "frontend-abc123",
	}
	if err := st.PutIdentity(ctx, ident); err != nil {
		t.Fatalf("put identity: %v", err)
	}
	waitForEvent(t, events, control.StoreEventIdentityChanged)

	ids, err := st.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(ids) != 1 || ids[0] != ident {
		t.Fatalf("identities = %+v, want exactly %+v", ids, ident)
	}

	// Deletes must propagate too.
	if err := st.DeletePolicy(ctx, rule.Key); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	waitForEvent(t, events, control.StoreEventPolicyChanged)
	rules, err = st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies after delete: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("policies after delete = %+v, want empty", rules)
	}
}

// waitForEvent drains events until one of the wanted kind arrives. The etcd
// store delivers both local-notify and etcd-watch events, so duplicates and
// interleavings of the other kind are tolerated.
func waitForEvent(t *testing.T, events <-chan control.StoreEvent, want control.StoreEventKind) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("watch channel closed while waiting for event kind %v", want)
			}
			if ev.Kind == want {
				return
			}
		case <-deadline:
			t.Fatalf("no StoreEvent of kind %v within 10s", want)
		}
	}
}
