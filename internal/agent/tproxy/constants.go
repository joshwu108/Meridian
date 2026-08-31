package tproxy

// TproxyMark is the fwmark bit set by tc_ingress on a REDIRECT verdict SYN
// (ADR-0006 D-A). It must match the TPROXY_MARK constant in the eBPF program.
const TproxyMark = uint32(0x1)

// TproxyTable is the routing table used for TPROXY-marked packet delivery.
const TproxyTable = 100

// OutboundPort is the node proxy's outbound intercept transparent listener.
const OutboundPort = 15001

// InboundPort is the node proxy's inbound mTLS transparent listener.
const InboundPort = 15008
