//go:build linux

package datapath

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
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
	v := reflect.ValueOf(identity)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !isIdentityIPFieldName(f.Name) {
			continue
		}
		key, ok := reflectFieldIPv4NetworkKey(v.Field(i))
		if ok {
			return key, nil
		}
	}
	return 0, fmt.Errorf("translate identity id=%d: missing IPv4 field on wire.Identity", identity.ID)
}

func isIdentityIPFieldName(name string) bool {
	switch name {
	case "PodIPv4", "PodIP", "IP", "IPv4":
		return true
	default:
		return false
	}
}

func reflectFieldIPv4NetworkKey(field reflect.Value) (uint32, bool) {
	if !field.IsValid() {
		return 0, false
	}

	if field.Kind() == reflect.Pointer {
		if field.IsNil() {
			return 0, false
		}
		return reflectFieldIPv4NetworkKey(field.Elem())
	}

	if field.Type() == reflect.TypeOf(netip.Addr{}) {
		addr := field.Interface().(netip.Addr)
		if !addr.Is4() {
			return 0, false
		}
		v4 := addr.As4()
		return binary.BigEndian.Uint32(v4[:]), true
	}

	if field.Type() == reflect.TypeOf(net.IP{}) {
		ip := field.Interface().(net.IP).To4()
		if ip == nil {
			return 0, false
		}
		return binary.BigEndian.Uint32(ip), true
	}

	if field.Kind() == reflect.String {
		addr, err := netip.ParseAddr(field.String())
		if err != nil || !addr.Is4() {
			return 0, false
		}
		v4 := addr.As4()
		return binary.BigEndian.Uint32(v4[:]), true
	}

	return 0, false
}

var (
	_ [12 - unsafe.Sizeof(policyMapKey{})]byte
	_ [4 - unsafe.Sizeof(policyMapVerdict{})]byte
)
