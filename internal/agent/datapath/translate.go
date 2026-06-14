//go:build linux

package datapath

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/joshuawu/meridian/pkg/wire"
)

type policyMapKey struct {
	SrcID     uint32
	DstID     uint32
	DstPort   uint16
	Proto     uint8
	Direction uint8
}

type policyMapVerdict struct {
	Action uint8
	Flags  uint8
	Pad    uint16
}

type identityMapEntry struct {
	Key   uint32
	Value uint32
}

func translatePolicyRuleKey(key wire.PolicyRuleKey) policyMapKey {
	return policyMapKey{
		SrcID:     uint32(key.SrcIdentity),
		DstID:     uint32(key.DstIdentity),
		DstPort:   key.DstPort,
		Proto:     key.Protocol,
		Direction: uint8(key.Direction),
	}
}

func translatePolicyVerdict(verdict wire.PolicyVerdict) policyMapVerdict {
	return policyMapVerdict{
		Action: uint8(verdict.Action),
		Flags:  uint8(verdict.Flags),
		Pad:    0,
	}
}

func translateIdentity(identity wire.Identity) (identityMapEntry, error) {
	ipv4Key, err := identityIPv4NetworkKey(identity)
	if err != nil {
		return identityMapEntry{}, err
	}
	return identityMapEntry{
		Key:   ipv4Key,
		Value: uint32(identity.ID),
	}, nil
}

func identityIPv4NetworkKey(identity wire.Identity) (uint32, error) {
	if identity.PodIPv4 == "" {
		return 0, fmt.Errorf("translate identity id=%d: missing pod_ipv4", identity.ID)
	}
	addr, err := netip.ParseAddr(identity.PodIPv4)
	if err != nil {
		return 0, fmt.Errorf("translate identity id=%d pod_ipv4=%q: parse: %w", identity.ID, identity.PodIPv4, err)
	}
	if !addr.Is4() {
		return 0, fmt.Errorf("translate identity id=%d pod_ipv4=%q: not IPv4", identity.ID, identity.PodIPv4)
	}
	v4 := addr.As4()
	// identity_map keys are pod IPv4 in network byte order. On little-endian
	// hosts the uint32 passed to bpf.Map.Update must use the same 4-byte layout
	// BPF reads from ip->saddr (see test/bpf keyFromIPv4Wire).
	return binary.LittleEndian.Uint32(v4[:]), nil
}

var (
	_ [12 - unsafe.Sizeof(policyMapKey{})]byte
	_ [4 - unsafe.Sizeof(policyMapVerdict{})]byte
)
