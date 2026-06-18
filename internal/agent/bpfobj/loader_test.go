//go:build bpf

package bpfobj

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/test/harness"
)

// TestSchemaVersionSingleSourced closes MER-33 / review D-1: the loader must
// read MERIDIAN_SCHEMA_VERSION from bpf2go-generated bindings, not a
// hand-mirrored Go literal. A drift between C and Go would otherwise only be
// caught by humans.
func TestSchemaVersionSingleSourced(t *testing.T) {
	want := uint32(bpf.CounterMeridianSchemaVersionMERIDIAN_SCHEMA_VERSION)
	if want == 0 {
		t.Fatal("bpf2go exported MERIDIAN_SCHEMA_VERSION is 0 — enum not in BTF?")
	}
	if schemaVersion != want {
		t.Fatalf("loader schemaVersion = %d, want bpf2go constant %d", schemaVersion, want)
	}
	if want != 2 {
		t.Fatalf("MERIDIAN_SCHEMA_VERSION = %d, want 2 (Phase 1 contract freeze)", want)
	}
}

// TestSchemaSentinelFailsClosedOnV1Pins closes review T-2 via MER-33: a pin set
// stamped with schema v1 must be refused by the v2 build. Distinct from the
// partial-init case (ErrPartialPinSet) and from an arbitrary foreign version.
func TestSchemaSentinelFailsClosedOnV1Pins(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)

	objs, err := LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	const v1 uint32 = 1
	if err := objs.SchemaSentinelMap.Put(uint32(0), v1); err != nil {
		objs.Close()
		t.Fatalf("overwrite sentinel to v1: %v", err)
	}
	objs.Close()

	reopened, err := LoadCounter(pinDir)
	if err == nil {
		reopened.Close()
		t.Fatal("LoadCounter accepted v1 pins on a v2 build; want fail-closed")
	}
	if errors.Is(err, ErrPartialPinSet) {
		t.Fatalf("LoadCounter error = %v, want version-mismatch fail-closed, not ErrPartialPinSet", err)
	}
}

// TestSockhashSurvivesAgentRestart_MER58 proves the restart-survival contract for
// the SOCKMAP fast path: on (re)start the bpfobj loader RE-OPENS the pinned
// `sockhash` (LIBBPF_PIN_BY_NAME + PinPath) rather than creating a fresh one, so
// the established sockets it holds survive an agent restart. The datapath
// deliberately leaves pins in place on shutdown (ARCHITECTURE lifecycle); the
// bpffs pin keeps the map — and its socket entries — alive across the gap.
//
// Two assertions: (a) the re-opened sockhash is the SAME kernel object (identical
// map ID) — recreation would silently drop all live redirect state; and (b) a real
// established-socket entry inserted before the restart is still present after it.
func TestSockhashSurvivesAgentRestart_MER58(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	pinDir := harness.PinDir(t)

	// First start: creates + pins the sockhash.
	sk1, err := LoadSkMsg(pinDir)
	if err != nil {
		t.Fatalf("first LoadSkMsg: %v", err)
	}
	id1 := sockhashMapID(t, sk1.Sockhash)

	// Insert a real established socket under a known key, then confirm it is present.
	key := mer58SockKey("127.0.0.1", 54321)
	closeConns := insertEstablishedSocket(t, sk1.Sockhash, key)
	defer closeConns()
	if !mer58SockhashHasKey(t, sk1.Sockhash, key) {
		_ = sk1.Close()
		t.Fatalf("precondition: inserted sockhash key %+v not present before restart", key)
	}

	// Simulate the agent stopping: close all fds. The bpffs pin keeps the map alive.
	if err := sk1.Close(); err != nil {
		t.Fatalf("close first load (simulated stop): %v", err)
	}

	// Restart: a fresh load must RE-OPEN the pinned sockhash, not recreate it.
	sk2, err := LoadSkMsg(pinDir)
	if err != nil {
		t.Fatalf("restart LoadSkMsg: %v", err)
	}
	defer sk2.Close()

	// (a) same kernel object → re-opened, not recreated.
	if id2 := sockhashMapID(t, sk2.Sockhash); id2 != id1 {
		t.Fatalf("sockhash was recreated on restart: map ID %d -> %d (live redirect state lost)", id1, id2)
	}
	// (b) the established-socket entry survived the restart.
	if !mer58SockhashHasKey(t, sk2.Sockhash, key) {
		t.Fatalf("sockhash entry %+v did not survive agent restart (pin recreated, not re-opened)", key)
	}
}

func sockhashMapID(t *testing.T, m *ebpf.Map) ebpf.MapID {
	t.Helper()
	info, err := m.Info()
	if err != nil {
		t.Fatalf("sockhash map info: %v", err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatalf("sockhash map info has no ID")
	}
	return id
}

// mer58SockKey builds the canonical sock_key (CC-6 / D18: dst_ip + dst_port in
// network byte order). Local copy so this loader test does not depend on the
// test/bpf package's helpers.
func mer58SockKey(ip string, port int) bpf.CounterSockKey {
	v4 := net.ParseIP(ip).To4()
	var be2 [2]byte
	binary.BigEndian.PutUint16(be2[:], uint16(port))
	return bpf.CounterSockKey{
		// Wire (network-order) bytes reproduced via the native marshaling ebpf
		// uses for map keys — matches the datapath's keyFromIPv4Wire convention.
		DstIp:   binary.NativeEndian.Uint32(v4),
		DstPort: binary.NativeEndian.Uint16(be2[:]),
		Pad:     0,
	}
}

// mer58SockhashHasKey reports whether want is present, walking keys with NextKey
// (SOCKHASH values are sockets and are not read back).
func mer58SockhashHasKey(t *testing.T, m *ebpf.Map, want bpf.CounterSockKey) bool {
	t.Helper()
	var next bpf.CounterSockKey
	err := m.NextKey(nil, &next)
	for err == nil {
		if next == want {
			return true
		}
		cur := next
		err = m.NextKey(&cur, &next)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("iterate sockhash: %v", err)
	}
	return false
}

// insertEstablishedSocket dials a loopback TCP connection and inserts the
// established client socket into the sockhash under key (a userspace SOCKHASH
// update takes a socket fd as the value). The returned func closes the sockets.
func insertEstablishedSocket(t *testing.T, m *ebpf.Map, key bpf.CounterSockKey) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		accCh <- accepted{c, e}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial: %v", err)
	}
	acc := <-accCh
	if acc.err != nil {
		_ = conn.Close()
		_ = ln.Close()
		t.Fatalf("accept: %v", acc.err)
	}

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("conn is %T, want *net.TCPConn", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	var updErr error
	if cErr := raw.Control(func(fd uintptr) {
		// SOCKHASH update: value is the socket fd (value size is __u64, D18).
		updErr = m.Update(key, uint64(fd), ebpf.UpdateAny)
	}); cErr != nil {
		t.Fatalf("raw control: %v", cErr)
	}
	if updErr != nil {
		t.Fatalf("insert established socket into sockhash: %v", updErr)
	}

	return func() {
		_ = conn.Close()
		if acc.c != nil {
			_ = acc.c.Close()
		}
		_ = ln.Close()
	}
}
