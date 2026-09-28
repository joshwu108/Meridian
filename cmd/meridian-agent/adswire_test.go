package main

import (
	"testing"

	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/pkg/wire"
)

// TestNewPostApplyUpdatesResolver verifies the post-apply hook refreshes the
// SPIFFE ID resolver from the client's full applied identity set.
func TestNewPostApplyUpdatesResolver(t *testing.T) {
	res := proxy.NewMapSpiffeIDResolver()
	applied := []wire.Identity{
		{ID: 5, SpiffeID: "spiffe://cluster.local/ns/a/sa/web"},
		{ID: 6, SpiffeID: "spiffe://cluster.local/ns/b/sa/api"},
	}
	fn := newPostApply(func() []wire.Identity { return applied }, res)

	// The plan content is irrelevant — the hook always reloads the full set.
	fn(wire.CommitPlan{})

	if id, ok := res.ResolveSpiffeID("spiffe://cluster.local/ns/a/sa/web"); !ok || id != 5 {
		t.Fatalf("ResolveSpiffeID = (%d, %v), want (5, true)", id, ok)
	}
	if uri, ok := res.LookupID(6); !ok || uri != "spiffe://cluster.local/ns/b/sa/api" {
		t.Fatalf("LookupID(6) = (%q, %v)", uri, ok)
	}

	// A later apply with a shrunk set fully replaces the previous mapping.
	applied = applied[:1]
	fn(wire.CommitPlan{})
	if _, ok := res.LookupID(6); ok {
		t.Fatal("identity 6 survived resolver refresh after removal")
	}
}

// TestADSDialOptionInsecureWithoutBootstrap verifies dev-mode dialing works
// without a bootstrap credential.
func TestADSDialOptionInsecureWithoutBootstrap(t *testing.T) {
	opt, err := adsDialOption("", "")
	if err != nil {
		t.Fatalf("adsDialOption without bootstrap: %v", err)
	}
	if opt == nil {
		t.Fatal("adsDialOption returned nil DialOption")
	}
}

// TestADSDialOptionMTLSWithBootstrap verifies the mTLS path builds from the
// bootstrap credential files.
func TestADSDialOptionMTLSWithBootstrap(t *testing.T) {
	certPath, keyPath := writeBootstrapFiles(t)
	opt, err := adsDialOption(certPath, keyPath)
	if err != nil {
		t.Fatalf("adsDialOption with bootstrap: %v", err)
	}
	if opt == nil {
		t.Fatal("adsDialOption returned nil DialOption")
	}
}

func TestADSDialOptionBadBootstrapFails(t *testing.T) {
	if _, err := adsDialOption("/nonexistent/boot.crt", "/nonexistent/boot.key"); err == nil {
		t.Fatal("expected error for unreadable bootstrap files, got nil")
	}
}
