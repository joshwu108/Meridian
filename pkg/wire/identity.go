// Package wire holds Meridian's cross-boundary contracts shared by the
// control plane, agent, and node proxy.
//
// This package is a LEAF: it imports only the Go standard library. It must
// never import internal/..., bpf/, or any third-party package (enforced by
// depguard; see .golangci.yml). Anything reachable from both the control
// plane and the data plane lives here.
package wire

// IdentityID is the numeric workload identity stored in the kernel
// identity_map and policy_map keys, and carried across nodes in the Geneve
// identity option. The control plane is the SOLE allocator (CC-3): IDs are
// cluster-global, allocated monotonically, and never reused within a
// control-plane lifetime.
type IdentityID uint32

// IdentityUnknown is the reserved "unknown / not in identity_map" value.
// Kernel programs treat it per the CC-5 unknown-identity posture.
const IdentityUnknown IdentityID = 0
