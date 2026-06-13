package telemetry

import (
	"net"
	"testing"
	"time"
)

// htons builds a network-order uint16 from a host-order port, matching how the
// kernel stores ports in the wire struct on a little-endian host.
func htons(host uint16) uint16 { return (host >> 8) | (host << 8) }

func TestWallClockMath(t *testing.T) {
	// Arrange: a fixed boot offset of one hour.
	bootNs := int64(time.Hour)

	// Act + Assert: a known monotonic value lands at monotonic + offset.
	const monoNs = uint64(123_456_789)
	got := wallClock(monoNs, bootNs)
	want := time.Unix(0, int64(monoNs)+bootNs)
	if !got.Equal(want) {
		t.Fatalf("wallClock(%d) = %v, want %v", monoNs, got, want)
	}

	// Zero monotonic => zero time (event with no timestamp).
	if z := wallClock(0, bootNs); !z.IsZero() {
		t.Fatalf("wallClock(0) = %v, want zero time", z)
	}
}

func TestNtohsRoundTrip(t *testing.T) {
	for _, p := range []uint16{0, 1, 80, 443, 8080, 54321, 65535} {
		if got := ntohs(htons(p)); got != p {
			t.Errorf("ntohs(htons(%d)) = %d", p, got)
		}
	}
}

func TestIPFromBE32(t *testing.T) {
	// Arrange: 10.0.0.5 as it sits in kernel memory (network-order bytes)
	// loaded as a little-endian uint32: first address byte is the LSB.
	be := uint32(10) | uint32(0)<<8 | uint32(0)<<16 | uint32(5)<<24

	// Act
	ip := ipFromBE32(be)

	// Assert
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("ipFromBE32 = %v, want 10.0.0.5", ip)
	}
}
