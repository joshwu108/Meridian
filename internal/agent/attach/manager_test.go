//go:build linux && integration

package attach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/test/harness"
)

func TestMain(m *testing.M) {
	harness.Reap()
	code := m.Run()
	harness.Reap()
	os.Exit(code)
}

func TestEnsureAttachedWorks(t *testing.T) {
	harness.RequireRoot(t)
	manager, iface := setupManagerAndIface(t)

	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("EnsureAttached failed: %v", err)
	}

	assertHasClsact(t, iface)
	assertFilterCount(t, iface, defaultFilterName, 1)
}

func TestDetachWorks(t *testing.T) {
	harness.RequireRoot(t)
	manager, iface := setupManagerAndIface(t)

	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("EnsureAttached failed: %v", err)
	}
	if err := manager.Detach(context.Background(), iface); err != nil {
		t.Fatalf("Detach failed: %v", err)
	}

	assertFilterCount(t, iface, defaultFilterName, 0)
	assertNoClsact(t, iface)
}

func TestDetachTwiceIsIdempotent(t *testing.T) {
	harness.RequireRoot(t)
	manager, iface := setupManagerAndIface(t)

	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("EnsureAttached failed: %v", err)
	}
	if err := manager.Detach(context.Background(), iface); err != nil {
		t.Fatalf("first Detach failed: %v", err)
	}
	if err := manager.Detach(context.Background(), iface); err != nil {
		t.Fatalf("second Detach failed: %v", err)
	}
}

func TestDetachOnDeletedLinkIsNoOp(t *testing.T) {
	harness.RequireRoot(t)
	manager, iface := setupManagerAndIface(t)

	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("EnsureAttached failed: %v", err)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", iface, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("LinkDel(%s): %v", iface, err)
	}

	if err := manager.Detach(context.Background(), iface); err != nil {
		t.Fatalf("Detach on deleted link should be no-op: %v", err)
	}
}

func TestEnsureAttachedTwiceIsNoOp(t *testing.T) {
	harness.RequireRoot(t)
	manager, iface := setupManagerAndIface(t)

	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("first EnsureAttached failed: %v", err)
	}
	if err := manager.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("second EnsureAttached failed: %v", err)
	}

	assertFilterCount(t, iface, defaultFilterName, 1)
}

func TestRestartSucceedsWithPinnedProgram(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	progPin := filepath.Join(pinDir, "counter_prog")
	v := harness.NewVethPair(t, "restart", 23)
	iface := v.HostVeth

	objsA, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("first load counter: %v", err)
	}
	t.Cleanup(func() { _ = objsA.Close() })
	mgrA := NewManager(objsA.MeridianCounter, progPin)
	if err := mgrA.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("first EnsureAttached failed: %v", err)
	}

	objsB, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("second load counter: %v", err)
	}
	t.Cleanup(func() { _ = objsB.Close() })
	mgrB := NewManager(objsB.MeridianCounter, progPin)
	if err := mgrB.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("restart EnsureAttached failed: %v", err)
	}

	assertFilterCount(t, iface, defaultFilterName, 1)
}

func TestReplaceProgramSucceeds(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	v := harness.NewVethPair(t, "replace", 24)
	iface := v.HostVeth

	objsA, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("first load counter: %v", err)
	}
	t.Cleanup(func() { _ = objsA.Close() })
	mgr := NewManager(objsA.MeridianCounter, filepath.Join(pinDir, "counter_prog_a"))
	if err := mgr.EnsureAttached(context.Background(), iface); err != nil {
		t.Fatalf("first EnsureAttached failed: %v", err)
	}

	objsB, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("second load counter: %v", err)
	}
	t.Cleanup(func() { _ = objsB.Close() })
	if err := mgr.ReplaceProgram(context.Background(), iface, objsB.MeridianCounter, filepath.Join(pinDir, "counter_prog_b")); err != nil {
		t.Fatalf("ReplaceProgram failed: %v", err)
	}

	assertFilterCount(t, iface, defaultFilterName, 1)
}

func setupManagerAndIface(t *testing.T) (*TCManager, string) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	objs, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("load counter: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	v := harness.NewVethPair(t, "attach", 22)
	progPin := filepath.Join(pinDir, "counter_prog")
	return NewManager(objs.MeridianCounter, progPin), v.HostVeth
}

func assertHasClsact(t *testing.T, ifName string) {
	t.Helper()
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", ifName, err)
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		t.Fatalf("QdiscList(%s): %v", ifName, err)
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			return
		}
	}
	t.Fatalf("clsact qdisc not found on %s", ifName)
}

func assertNoClsact(t *testing.T, ifName string) {
	t.Helper()
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", ifName, err)
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		t.Fatalf("QdiscList(%s): %v", ifName, err)
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			t.Fatalf("unexpected clsact qdisc on %s", ifName)
		}
	}
}

func assertFilterCount(t *testing.T, ifName, filterName string, want int) {
	t.Helper()
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", ifName, err)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatalf("FilterList(%s): %v", ifName, err)
	}
	count := 0
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bpf.Name == filterName {
			count++
		}
	}
	if count != want {
		t.Fatalf("filter %q count=%d want=%d", filterName, count, want)
	}
}
