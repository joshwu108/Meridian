//go:build linux

package metrics

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/joshuawu/meridian/internal/agent/identitytable"
	"github.com/joshuawu/meridian/pkg/wire"
)

const unknownLabelValue = "unknown"

// DropReason values mirror enum drop_reason in bpf/include/meridian_types.h.
const (
	DropReasonUnspecified      uint32 = 0
	DropReasonPolicyDeny       uint32 = 1
	DropReasonPolicyMiss       uint32 = 2
	DropReasonUnknownIdentity  uint32 = 3
	DropReasonInvalidAction    uint32 = 4
	DropReasonGeneveEncapFail  uint32 = 5
)

type deniedFlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad     [3]uint8
}

type deniedFlowInfo struct {
	LastNs uint64
	Count  uint32
	Reason uint32
}

// DeniedFlow is one denied_flows_map entry joined with resolved SPIFFE names.
type DeniedFlow struct {
	SrcIP       netip.Addr
	DstIP       netip.Addr
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	Count       uint32
	Reason      uint32
	LastNs      uint64
	SrcIdentity string
	DstIdentity string
}

// DeniedReader reads denied_flows_map and joins identity names.
type DeniedReader interface {
	ReadAll(context.Context) ([]DeniedFlow, error)
}

// MapDeniedReader joins denied_flows_map with identity_map and a Resolver.
type MapDeniedReader struct {
	deniedMap   *ebpf.Map
	identityMap *ebpf.Map
	resolver    identitytable.Resolver
}

// NewMapDeniedReader builds a denied-flow reader over pinned maps.
func NewMapDeniedReader(deniedMap, identityMap *ebpf.Map, resolver identitytable.Resolver) *MapDeniedReader {
	return &MapDeniedReader{
		deniedMap:   deniedMap,
		identityMap: identityMap,
		resolver:    resolver,
	}
}

// ReadAll returns every denied flow with SPIFFE labels resolved.
func (r *MapDeniedReader) ReadAll(ctx context.Context) ([]DeniedFlow, error) {
	if r == nil || r.deniedMap == nil {
		return nil, fmt.Errorf("metrics: nil denied_flows_map")
	}

	var (
		key   deniedFlowKey
		value deniedFlowInfo
	)
	out := make([]DeniedFlow, 0)
	iter := r.deniedMap.Iterate()
	for iter.Next(&key, &value) {
		srcID, _ := lookupIdentityID(r.identityMap, key.SrcIP)
		dstID, _ := lookupIdentityID(r.identityMap, key.DstIP)
		out = append(out, DeniedFlow{
			SrcIP:       ipv4FromNetwork(key.SrcIP),
			DstIP:       ipv4FromNetwork(key.DstIP),
			SrcPort:     hostPortFromFlowKey(key.SrcPort),
			DstPort:     hostPortFromFlowKey(key.DstPort),
			Proto:       key.Proto,
			Count:       value.Count,
			Reason:      value.Reason,
			LastNs:      value.LastNs,
			SrcIdentity: resolveSpiffeLabel(ctx, r.resolver, srcID),
			DstIdentity: resolveSpiffeLabel(ctx, r.resolver, dstID),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("metrics: iterate denied_flows_map: %w", err)
	}
	return out, nil
}

type deniedCollector struct {
	reader DeniedReader
	desc   *prometheus.Desc
}

// NewDeniedCollector exposes denied_flows_map entries with SPIFFE identity labels.
func NewDeniedCollector(reader DeniedReader) prometheus.Collector {
	return &deniedCollector{
		reader: reader,
		desc: prometheus.NewDesc(
			"meridian_denied_flow_packets_total",
			"Total dropped packets per denied flow keyed by resolved SPIFFE identities.",
			[]string{"src_identity", "dst_identity", "dst_port", "protocol", "reason"},
			nil,
		),
	}
}

func (c *deniedCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *deniedCollector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.reader == nil {
		return
	}

	flows, err := c.reader.ReadAll(context.Background())
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.desc, err)
		return
	}

	for _, flow := range flows {
		ch <- prometheus.MustNewConstMetric(
			c.desc,
			prometheus.CounterValue,
			float64(flow.Count),
			flow.SrcIdentity,
			flow.DstIdentity,
			strconv.Itoa(int(flow.DstPort)),
			protocolLabel(flow.Proto),
			dropReasonLabel(flow.Reason),
		)
	}
}

func lookupIdentityID(m *ebpf.Map, ipv4NetworkOrder uint32) (wire.IdentityID, bool) {
	if m == nil {
		return 0, false
	}
	var id uint32
	if err := m.Lookup(ipv4NetworkOrder, &id); err != nil {
		return 0, false
	}
	return wire.IdentityID(id), true
}

func resolveSpiffeLabel(ctx context.Context, resolver identitytable.Resolver, id wire.IdentityID) string {
	if resolver == nil || id == wire.IdentityUnknown {
		return unknownLabelValue
	}
	identity, ok, err := resolver.Resolve(ctx, id)
	if err != nil || !ok {
		return unknownLabelValue
	}
	if strings.TrimSpace(identity.SpiffeID) == "" {
		return unknownLabelValue
	}
	return identity.SpiffeID
}

func ipv4FromNetwork(raw uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], raw)
	return netip.AddrFrom4(b)
}

func hostPortFromFlowKey(port uint16) uint16 {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], port)
	return binary.BigEndian.Uint16(buf[:])
}

func protocolLabel(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}

func dropReasonLabel(reason uint32) string {
	switch reason {
	case DropReasonPolicyDeny:
		return "policy_deny"
	case DropReasonPolicyMiss:
		return "policy_miss"
	case DropReasonUnknownIdentity:
		return "unknown_identity"
	case DropReasonInvalidAction:
		return "invalid_action"
	case DropReasonGeneveEncapFail:
		return "geneve_encap_fail"
	default:
		return "unspecified"
	}
}
