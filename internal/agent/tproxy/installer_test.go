package tproxy

import (
	"testing"
)

// TestTproxyConstants verifies that the exported constants match expected values
// (regression guard against accidental changes to the eBPF mark contract).
func TestTproxyConstants(t *testing.T) {
	if TproxyMark != 0x1 {
		t.Fatalf("TproxyMark = 0x%x, want 0x1", TproxyMark)
	}
	if OutboundPort != 15001 {
		t.Fatalf("OutboundPort = %d, want 15001", OutboundPort)
	}
	if InboundPort != 15008 {
		t.Fatalf("InboundPort = %d, want 15008", InboundPort)
	}
}
