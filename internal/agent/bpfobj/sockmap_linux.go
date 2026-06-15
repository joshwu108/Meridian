//go:build linux

package bpfobj

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/bpf"
)

// SockOpsObjects is the bpf2go-generated sock_ops collection (MER-47/48).
// Re-exported so callers reach through bpfobj — the sole bpf/ opener — without
// importing bpf/ directly (depguard wire-bpf-bridge).
type SockOpsObjects = bpf.SockOpsObjects

// SkMsgObjects is the bpf2go-generated sk_msg collection (MER-47/50).
type SkMsgObjects = bpf.SkMsgObjects

// LoadSockOps loads the Phase-2 sock_ops collection, RE-OPENING the shared maps
// (sockhash / identity_map / policy_map / metrics_map) already pinned by name
// under pinDir by the primary load. It is a SECONDARY loader: the primary
// LoadCounter / LoadTcIngress in the same startup owns and reconciles the schema
// sentinel, so this loader neither stamps nor re-verifies it — it only needs the
// shared pinned maps plus the sock_ops program for the cgroup attach (MER-57).
func LoadSockOps(pinDir string) (*SockOpsObjects, error) {
	if _, err := preparePinDir(pinDir); err != nil {
		return nil, err
	}
	var objs bpf.SockOpsObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	if err := bpf.LoadSockOpsObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("bpfobj: load sock_ops objects: %w", err)
	}
	return &objs, nil
}

// LoadSkMsg loads the Phase-2 sk_msg collection, re-opening the shared `sockhash`
// (and metrics) maps pinned under pinDir. Secondary loader; see LoadSockOps on
// the schema-sentinel ownership contract. The returned program + Sockhash map fd
// drive the BPF_SK_MSG_VERDICT attach (MER-57).
func LoadSkMsg(pinDir string) (*SkMsgObjects, error) {
	if _, err := preparePinDir(pinDir); err != nil {
		return nil, err
	}
	var objs bpf.SkMsgObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	if err := bpf.LoadSkMsgObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("bpfobj: load sk_msg objects: %w", err)
	}
	return &objs, nil
}
