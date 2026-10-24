package main

import (
	"errors"
	"testing"
)

// recordingPutter captures every write made to the runtime_config_map seam.
type recordingPutter struct {
	keys   []any
	values []any
	err    error
}

func (p *recordingPutter) Put(key, value any) error {
	p.keys = append(p.keys, key)
	p.values = append(p.values, value)
	return p.err
}

// TestRuntimeConfigWord pins the bit layout written for each posture. The
// whole word is authoritative, so fail-closed must be an explicit zero and
// not "leave whatever the pin already had".
func TestRuntimeConfigWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fallOpen bool
		want     uint32
	}{
		{name: "fail closed is an explicit zero word", fallOpen: false, want: 0},
		{name: "fallopen sets MERIDIAN_CFG_FALLOPEN_UNKNOWN", fallOpen: true, want: 1 << 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := runtimeConfigWord(tc.fallOpen); got != tc.want {
				t.Errorf("runtimeConfigWord(%v) = %#x, want %#x", tc.fallOpen, got, tc.want)
			}
		})
	}
}

// TestSeedRuntimeConfigWritesPostureToSlotZero is the wiring test: the flag
// must reach the map as exactly one write of the right word to slot 0.
func TestSeedRuntimeConfigWritesPostureToSlotZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fallOpen bool
		wantVal  uint32
	}{
		{name: "default fail-closed", fallOpen: false, wantVal: 0},
		{name: "--policy-fallopen=true", fallOpen: true, wantVal: cfgFallOpenUnknownBit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			put := &recordingPutter{}
			if err := seedRuntimeConfig(put, tc.fallOpen); err != nil {
				t.Fatalf("seedRuntimeConfig(%v) = %v, want nil", tc.fallOpen, err)
			}

			if len(put.keys) != 1 {
				t.Fatalf("got %d writes, want exactly 1 (keys=%v)", len(put.keys), put.keys)
			}
			gotKey, ok := put.keys[0].(uint32)
			if !ok {
				t.Fatalf("key written as %T, want uint32 (map key type is __u32)", put.keys[0])
			}
			if gotKey != cfgSlotRuntimeFlags {
				t.Errorf("wrote slot %d, want %d", gotKey, cfgSlotRuntimeFlags)
			}
			gotVal, ok := put.values[0].(uint32)
			if !ok {
				t.Fatalf("value written as %T, want uint32 (map value type is __u32)", put.values[0])
			}
			if gotVal != tc.wantVal {
				t.Errorf("wrote %#x, want %#x", gotVal, tc.wantVal)
			}
		})
	}
}

// TestSeedRuntimeConfigPropagatesWriteFailure guards the fail-closed posture:
// a map write that silently failed would leave the agent attaching with an
// unknown posture, so the error must reach the caller and abort startup.
func TestSeedRuntimeConfigPropagatesWriteFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("bpf: map write refused")
	err := seedRuntimeConfig(&recordingPutter{err: sentinel}, true)
	if !errors.Is(err, sentinel) {
		t.Fatalf("seedRuntimeConfig error = %v, want wrapped %v", err, sentinel)
	}
}

// TestSeedRuntimeConfigRejectsNilMap covers the case where the pinned
// collection loaded but runtime_config_map came back absent.
func TestSeedRuntimeConfigRejectsNilMap(t *testing.T) {
	t.Parallel()

	if err := seedRuntimeConfig(nil, false); err == nil {
		t.Fatal("seedRuntimeConfig(nil, false) = nil, want an error")
	}
}

// TestFallOpenLogLine checks the operator-facing banner names the posture and
// the flag, since the fail-closed default is the one people misdiagnose.
func TestFallOpenLogLine(t *testing.T) {
	t.Parallel()

	if got := fallOpenLogLine(true); got != "policy fallopen: unknown identities will be ALLOWED (--policy-fallopen=true)" {
		t.Errorf("fallOpenLogLine(true) = %q", got)
	}
	if got := fallOpenLogLine(false); got != "policy fallopen: unknown identities DENIED (default fail-closed)" {
		t.Errorf("fallOpenLogLine(false) = %q", got)
	}
}
