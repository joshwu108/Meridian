// SPDX-License-Identifier: GPL-2.0
/*
 * tc_ingress.c — Phase 1 production ingress parser, identity resolution,
 * policy verdict enforcement, and decision-point telemetry.
 *
 * Scope:
 *   - Verifier-safe Ethernet / IPv4 / TCP / UDP parsing with explicit bounds checks.
 *   - src/dst identity lookups from identity_map (key = IPv4 BE bytes as loaded).
 *   - Unknown-identity posture toggle:
 *       * fail-closed (default) -> TC_ACT_SHOT
 *       * fail-open             -> TC_ACT_OK
 *   - policy_map lookup by host-order policy_key + ingress direction.
 *   - Decision-point event emission (TCP open / UDP first-sight / deny / redirect).
 *   - denied_flows_map upserts and flow/byte metrics accounting.
 *   - Non-IPv4 passthrough -> TC_ACT_OK.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "meridian_consts.h"
#include "meridian_maps.h"
#include "meridian_types.h"

/*
 * UDP first-sight gate for ALLOW telemetry:
 *   - key: flow_key (network order bytes from packet)
 *   - value: marker byte
 * LRU bounds memory and naturally ages out inactive flows.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MERIDIAN_UDP_SEEN_FLOWS_ENTRIES);
	__type(key, struct flow_key);
	__type(value, __u8);
} udp_seen_flows_map SEC(".maps");

static __always_inline __u32 failopen_unknown_enabled(void)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&runtime_config_map, &key);

	/* Default is fail-closed unless the operator explicitly enables fail-open. */
	if (!cfg)
		return 0;
	return (*cfg & MERIDIAN_CFG_FALLOPEN_UNKNOWN) != 0;
}

static __always_inline __u32 parse_l4_ports(struct iphdr *ip, void *data_end,
					    __u16 *src_port, __u16 *dst_port)
{
	__u32 ihl = ip->ihl;
	/*
	 * ip->ihl is a 4-bit field, but keep the explicit upper bound so the
	 * 5.15 verifier can constrain the range before pointer arithmetic.
	 */
	if (ihl < IPV4_IHL_MIN || ihl > IPV4_IHL_MAX)
		return 0;

	void *l4 = (void *)ip + ihl * IPV4_WORD_BYTES;
	if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
		if (l4 + L4_PORTS_BYTES > data_end)
			return 0;

		__be16 *ports = l4;
		*src_port = ports[0];
		*dst_port = ports[1];
	}
	return 1;
}

static __always_inline void metric_add(__u32 id, __u64 delta)
{
	__u64 *val = bpf_map_lookup_elem(&metrics_map, &id);

	if (val)
		__sync_fetch_and_add(val, delta);
}

static __always_inline void emit_flow_event(__u64 timestamp_ns, __u32 src_ip,
					    __u32 dst_ip, __u16 src_port,
					    __u16 dst_port, __u8 proto,
					    __u8 verdict, __u32 src_identity,
					    __u32 dst_identity, __u32 bytes)
{
	struct flow_event *ev = bpf_ringbuf_reserve(&flow_events, sizeof(*ev), 0);

	if (!ev) {
		metric_add(METRIC_RINGBUF_DROPPED, 1);
		return;
	}

	ev->timestamp_ns = timestamp_ns;
	ev->src_ip = src_ip;
	ev->dst_ip = dst_ip;
	ev->src_port = src_port;
	ev->dst_port = dst_port;
	ev->proto = proto;
	ev->verdict = verdict;
	ev->_pad0 = 0;
	ev->src_identity = src_identity;
	ev->dst_identity = dst_identity;
	ev->bytes = bytes;
	ev->_pad1 = 0;
	ev->latency_ns = 0;
	ev->l7_status_code = 0;
	ev->_pad2[0] = 0;
	ev->_pad2[1] = 0;
	ev->_pad2[2] = 0;

	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void denied_flow_upsert(struct flow_key *key, __u32 reason,
					       __u64 now_ns)
{
	struct deny_info info = {};
	struct deny_info *existing = bpf_map_lookup_elem(&denied_flows_map, key);

	if (existing)
		info.count = existing->count + 1;
	else
		info.count = 1;
	info.last_ns = now_ns;
	info.reason = reason;

	bpf_map_update_elem(&denied_flows_map, key, &info, BPF_ANY);
}

static __always_inline __u32 is_tcp_connection_open(struct iphdr *ip, void *data_end)
{
	__u32 ihl = ip->ihl;
	__u8 *l4;
	__u8 flags;

	if (ihl < IPV4_IHL_MIN || ihl > IPV4_IHL_MAX)
		return 0;

	l4 = (void *)ip + ihl * IPV4_WORD_BYTES;
	/* Need flags byte at TCP offset 13. */
	if (l4 + 14 > data_end)
		return 0;

	flags = l4[13];
	return (flags & 0x02) && !(flags & 0x10); /* SYN && !ACK */
}

static __always_inline __u32 udp_first_sight(struct flow_key *key)
{
	__u8 marker = 1;
	__u8 *seen = bpf_map_lookup_elem(&udp_seen_flows_map, key);

	if (seen)
		return 0;

	bpf_map_update_elem(&udp_seen_flows_map, key, &marker, BPF_ANY);
	return 1;
}

SEC("tc")
int meridian_tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 packet_bytes = skb->len;
	__u64 now_ns = bpf_ktime_get_ns();

	/* Byte counter is packet-based and increments on every packet. */
	metric_add(METRIC_BYTES_TOTAL, packet_bytes);

	/* Ethernet parse + bounds check. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Non-IPv4 always passes through in MER-16. */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* IPv4 fixed header parse + bounds check. */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* L4 parse (TCP/UDP only) with verifier-safe bounds checks. */
	__u16 src_port = 0;
	__u16 dst_port = 0;
	if (!parse_l4_ports(ip, data_end, &src_port, &dst_port)) {
		/* Parse failure is treated as unknown identity posture, not implicit allow. */
		if (failopen_unknown_enabled())
			return TC_ACT_OK;
		struct flow_key deny_key = {
			.src_ip = ip->saddr,
			.dst_ip = ip->daddr,
			.src_port = 0,
			.dst_port = 0,
			.proto = ip->protocol,
			._pad = {0, 0, 0},
		};

		denied_flow_upsert(&deny_key, DROP_REASON_UNKNOWN_IDENTITY, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, 0, 0, ip->protocol,
				FLOW_VERDICT_DENY, 0, 0, packet_bytes);
		return TC_ACT_SHOT;
	}

	/*
	 * Identity lookups. Keys are network-order packet bytes copied verbatim
	 * from the wire into ip->saddr/ip->daddr.
	 */
	__u32 src_key = ip->saddr;
	__u32 dst_key = ip->daddr;

	__u32 *src_identity = bpf_map_lookup_elem(&identity_map, &src_key);
	__u32 *dst_identity = bpf_map_lookup_elem(&identity_map, &dst_key);

	struct flow_key flow_key = {
		.src_ip = ip->saddr,
		.dst_ip = ip->daddr,
		.src_port = src_port,
		.dst_port = dst_port,
		.proto = ip->protocol,
		._pad = {0, 0, 0},
	};

	if (!src_identity || !dst_identity || *src_identity == 0 || *dst_identity == 0) {
		if (failopen_unknown_enabled())
			return TC_ACT_OK;
		denied_flow_upsert(&flow_key, DROP_REASON_UNKNOWN_IDENTITY, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, 0, 0, packet_bytes);
		return TC_ACT_SHOT;
	}

	struct policy_key policy_key = {
		.src_id = *src_identity,
		.dst_id = *dst_identity,
		.dst_port = bpf_ntohs(dst_port), /* host order for policy_map key */
		.proto = ip->protocol,
		.direction = POLICY_DIR_INGRESS,
	};
	struct policy_verdict *verdict = bpf_map_lookup_elem(&policy_map, &policy_key);

	if (!verdict) {
		denied_flow_upsert(&flow_key, DROP_REASON_POLICY_MISS, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, *src_identity,
				*dst_identity, packet_bytes);
		return TC_ACT_SHOT;
	}

	switch (verdict->action) {
	case FLOW_VERDICT_ALLOW:
		/*
		 * Decision-point ALLOW telemetry:
		 *   - TCP: emit once per connection on SYN&&!ACK
		 *   - UDP: emit only on first-sight via bounded LRU seen-set
		 */
		if ((ip->protocol == IPPROTO_TCP && is_tcp_connection_open(ip, data_end)) ||
		    (ip->protocol == IPPROTO_UDP && udp_first_sight(&flow_key))) {
			metric_add(METRIC_FLOWS_ALLOWED, 1);
			emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
					ip->protocol, FLOW_VERDICT_ALLOW, *src_identity,
					*dst_identity, packet_bytes);
		}
		return TC_ACT_OK;
	case FLOW_VERDICT_DENY:
		denied_flow_upsert(&flow_key, DROP_REASON_POLICY_DENY, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, *src_identity,
				*dst_identity, packet_bytes);
		return TC_ACT_SHOT;
	case FLOW_VERDICT_REDIRECT:
		/* MER-17 placeholder: decision + telemetry only, no data-path redirect yet. */
		skb->mark |= MERIDIAN_MARK_REDIRECT_PLACEHOLDER;
		metric_add(METRIC_FLOWS_REDIRECTED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_REDIRECT, *src_identity,
				*dst_identity, packet_bytes);
		return TC_ACT_OK;
	default:
		denied_flow_upsert(&flow_key, DROP_REASON_INVALID_ACTION, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, *src_identity,
				*dst_identity, packet_bytes);
		return TC_ACT_SHOT;
	}
}

char _license[] SEC("license") = "GPL";
