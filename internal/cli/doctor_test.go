package cli

import (
	"testing"
)

func TestKernelAtLeast(t *testing.T) {
	tests := []struct {
		ver          string
		major, minor int
		want         bool
	}{
		{"5.15.0-182", 5, 10, true},
		{"5.10.0", 5, 10, true},
		{"5.9.0", 5, 10, false},
		{"4.19.0", 5, 10, false},
		{"6.1.0", 5, 10, true},
		{"5.10.1-custom", 5, 10, true},
	}
	for _, tc := range tests {
		got := kernelAtLeast(tc.ver, tc.major, tc.minor)
		if got != tc.want {
			t.Errorf("kernelAtLeast(%q, %d, %d) = %v, want %v",
				tc.ver, tc.major, tc.minor, got, tc.want)
		}
	}
}

func TestDoctorOSProbe(t *testing.T) {
	r := probeOS(nil, Config{})
	// Just verify it runs without panic and returns a non-empty name/detail.
	if r.Name == "" {
		t.Fatal("empty probe name")
	}
	if r.Detail == "" {
		t.Fatal("empty probe detail")
	}
}
