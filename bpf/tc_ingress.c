// SPDX-License-Identifier: GPL-2.0
/*
 * tc_ingress.c — Phase 1 production ingress parser, identity resolution,
 * policy verdict enforcement, and decision-point telemetry.
 *
 * Scope:
 *   - Verifier-safe Ethernet / IPv4 / TCP / UDP parsing with explicit bounds checks.
 *   - Geneve pre-decap parse on underlay ingress (MER-21 / ADR-0002): recover
 *     remote src_identity from the Meridian identity TLV when the inner src IP
 *     is absent from the local identity_map.
 *   - src/dst identity lookups from identity_map (key = IPv4 BE bytes as loaded).
 *   - Unknown-identity posture toggle:
 *       * fail-closed (default) -> TC_ACT_SHOT
 *       * fail-open             -> TC_ACT_OK
 *   - policy_map lookup by host-order policy_key + ingress direction.
 *   - Decision-point event emission (TCP open / UDP first-sight / deny / redirect).
 *   - denied_flows_map upserts and flow/byte metrics accounting.
 *   - Non-IPv4 passthrough -> TC_ACT_OK.
 *   - 802.1Q VLAN unwrap for real pod links (MER-43): inner IPv4 parsed with
 *     the same bounds discipline as untagged frames.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "meridian_consts.h"
#include "meridian_maps.h"
#include "meridian_parse.h"
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

static __always_inline __u32 parse_geneve_identity(void *opts, void *data_end,
						   __u32 opt_bytes,
						   __u32 *src_id_out)
{
	__u32 offset = 0;

	*src_id_out = 0;

	for (int i = 0; i < 4; i++) {
		__u8 *opt;
		__u32 opt_len_words;
		__u32 opt_size;
		__u16 class_be;

		if (offset >= opt_bytes)
			break;
		if (offset > opt_bytes)
			return 0;

		opt = opts + offset;
		if (opt + 4 > (__u8 *)data_end)
			return 0;

		opt_len_words = opt[3] & 0x1f;
		opt_size = 4 + (opt_len_words * 4);
		if (opt_size < 4 || offset + opt_size > opt_bytes)
			return 0;

		class_be = *(__u16 *)&opt[0];
		if (class_be == bpf_htons(MERIDIAN_GENEVE_CLASS) &&
		    opt[2] == MERIDIAN_OPT_IDENTITY &&
		    opt_len_words == MERIDIAN_GENEVE_IDENTITY_LEN_WORDS) {
			__u32 src_id_be;

			if (opt + MERIDIAN_GENEVE_OPT_BYTES > (__u8 *)data_end)
				return 0;
			__builtin_memcpy(&src_id_be, &opt[4], sizeof(src_id_be));
			*src_id_out = bpf_ntohl(src_id_be);
			return 1;
		}
		offset += opt_size;
	}

	return 0;
}

/*
 * try_parse_geneve_inner attempts to peel a kernel-Geneve frame on underlay
 * ingress. On success it returns the inner IPv4 header and whether the Meridian
 * identity TLV was present. Missing TLV on a valid Geneve frame is surfaced via
 * geneve_tlv_found = 0 (MER-21 / ADR-0002).
 */
static __always_inline __u32 try_parse_geneve_inner(struct iphdr *outer_ip,
						    void *data_end,
						    struct iphdr **inner_ip_out,
						    __u32 *geneve_src_id_out,
						    __u32 *geneve_tlv_found_out)
{
	struct udphdr *udp;
	__u8 *geneve;
	__u32 opt_words;
	__u32 opt_bytes;
	__u8 *opts;
	__u8 *inner_base;
	struct iphdr *inner_ip;
	__u32 ignored_tlv = 0;

	if (outer_ip->protocol != IPPROTO_UDP)
		return 0;

	udp = (void *)outer_ip + outer_ip->ihl * IPV4_WORD_BYTES;
	if ((void *)(udp + 1) > data_end)
		return 0;
	if (udp->dest != bpf_htons(MERIDIAN_GENEVE_UDP_PORT))
		return 0;

	geneve = (void *)(udp + 1);
	if (geneve + 8 > (__u8 *)data_end)
		return 0;
	if ((geneve[0] >> 6) != 0)
		return 0;

	opt_words = geneve[0] & 0x3f;
	opt_bytes = opt_words * 4;
	if (opt_words > MERIDIAN_MAX_GENEVE_OPT_WORDS)
		return 0;

	opts = geneve + 8;
	if (opts + opt_bytes > (__u8 *)data_end)
		return 0;

	inner_base = opts + opt_bytes;
	if (!parse_ipv4_in_geneve_payload(inner_base, data_end, &inner_ip, &ignored_tlv))
		return 0;

	*inner_ip_out = inner_ip;
	*geneve_tlv_found_out = parse_geneve_identity(opts, data_end, opt_bytes,
						      geneve_src_id_out);
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
	if ((void *)(l4 + 14) > data_end)
		return 0;

	flags = l4[13];
	return (flags & 0x02) && !(flags & 0x10); /* SYN && !ACK */
}

static __always_inline __u32 is_geneve_tcp_client_syn(struct iphdr *ip, void *data_end)
{
	return is_tcp_connection_open(ip, data_end);
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

static __always_inline int enforce_flow(struct __sk_buff *skb, struct iphdr *ip,
					void *data_end, __u32 packet_bytes,
					__u64 now_ns, __u16 src_port,
					__u16 dst_port, __u32 src_id,
					__u32 dst_id, __u32 deny_action)
{
	struct flow_key flow_key = {
		.src_ip = ip->saddr,
		.dst_ip = ip->daddr,
		.src_port = src_port,
		.dst_port = dst_port,
		.proto = ip->protocol,
		._pad = {0, 0, 0},
	};

	if (src_id == 0 || dst_id == 0) {
		if (failopen_unknown_enabled())
			return TC_ACT_OK;
		denied_flow_upsert(&flow_key, DROP_REASON_UNKNOWN_IDENTITY, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, src_id, dst_id,
				packet_bytes);
		return TC_ACT_SHOT;
	}

	struct policy_key policy_key = {
		.src_id = src_id,
		.dst_id = dst_id,
		.dst_port = bpf_ntohs(dst_port),
		.proto = ip->protocol,
		.direction = POLICY_DIR_INGRESS,
	};
	struct policy_verdict *verdict = bpf_map_lookup_elem(&policy_map, &policy_key);

	if (!verdict) {
		denied_flow_upsert(&flow_key, DROP_REASON_POLICY_MISS, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, src_id, dst_id,
				packet_bytes);
		return TC_ACT_SHOT;
	}

	switch (verdict->action) {
	case FLOW_VERDICT_ALLOW:
		if ((ip->protocol == IPPROTO_TCP && is_tcp_connection_open(ip, data_end)) ||
		    (ip->protocol == IPPROTO_UDP && udp_first_sight(&flow_key))) {
			metric_add(METRIC_FLOWS_ALLOWED, 1);
			emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
					ip->protocol, FLOW_VERDICT_ALLOW, src_id, dst_id,
					packet_bytes);
		}
		return TC_ACT_OK;
	case FLOW_VERDICT_DENY:
		denied_flow_upsert(&flow_key, DROP_REASON_POLICY_DENY, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, src_id, dst_id,
				packet_bytes);
		return deny_action;
	case FLOW_VERDICT_REDIRECT:
		skb->mark |= MERIDIAN_MARK_REDIRECT_PLACEHOLDER;
		metric_add(METRIC_FLOWS_REDIRECTED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_REDIRECT, src_id, dst_id,
				packet_bytes);
		return TC_ACT_OK;
	default:
		denied_flow_upsert(&flow_key, DROP_REASON_INVALID_ACTION, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, ip->saddr, ip->daddr, src_port, dst_port,
				ip->protocol, FLOW_VERDICT_DENY, src_id, dst_id,
				packet_bytes);
		return TC_ACT_SHOT;
	}
}

static __always_inline __u32 is_geneve_udp_outer(struct iphdr *outer_ip, void *data_end)
{
	struct udphdr *udp;

	if (outer_ip->protocol != IPPROTO_UDP)
		return 0;

	udp = (void *)outer_ip + outer_ip->ihl * IPV4_WORD_BYTES;
	if ((void *)(udp + 1) > data_end)
		return 0;
	return udp->dest == bpf_htons(MERIDIAN_GENEVE_UDP_PORT);
}

SEC("tc")
int meridian_tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 packet_bytes = skb->len;
	__u64 now_ns = bpf_ktime_get_ns();
	struct iphdr *ip;
	struct iphdr *inner_ip = 0;
	__u16 src_port = 0;
	__u16 dst_port = 0;
	__u32 geneve_src_id = 0;
	__u32 geneve_tlv_found = 0;
	__u32 is_geneve = 0;
	__u32 src_id = 0;
	__u32 dst_id = 0;
	__u32 *mapped_src;
	__u32 *mapped_dst;

	metric_add(METRIC_PACKETS_TOTAL, 1);
	metric_add(METRIC_BYTES_TOTAL, packet_bytes);

	if (bpf_skb_pull_data(skb, skb->len))
		return TC_ACT_OK;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if (!parse_ipv4_after_eth(eth, data_end, &ip))
		return TC_ACT_OK;

	/*
	 * Parser-negative frames (bad IHL, truncated L4) pass through without
	 * policy enforcement — same discipline as counter.c / ARCHITECTURE §2.
	 */
	if (ip->ihl < IPV4_IHL_MIN || ip->ihl > IPV4_IHL_MAX)
		return TC_ACT_OK;

	is_geneve = try_parse_geneve_inner(ip, data_end, &inner_ip, &geneve_src_id,
					   &geneve_tlv_found);
	if (!is_geneve && is_geneve_udp_outer(ip, data_end))
		return TC_ACT_OK;
	if (is_geneve)
		ip = inner_ip;

	if (!parse_l4_ports(ip, data_end, &src_port, &dst_port))
		return TC_ACT_OK;

	mapped_src = bpf_map_lookup_elem(&identity_map, &ip->saddr);
	mapped_dst = bpf_map_lookup_elem(&identity_map, &ip->daddr);

	if (is_geneve && geneve_tlv_found)
		src_id = geneve_src_id;
	else if (mapped_src && *mapped_src != 0)
		src_id = *mapped_src;
	else if (is_geneve && !geneve_tlv_found)
		metric_add(METRIC_GENEVE_DECODE_FAIL, 1);

	if (mapped_dst && *mapped_dst != 0)
		dst_id = *mapped_dst;

	/*
	 * Geneve underlay ingress sees both directions. Enforce policy only on
	 * the initial client SYN once src_identity is known; return segments pass
	 * through (MER-21 gate). Missing TLV / unknown src must still fail closed.
	 */
	if (is_geneve && ip->protocol == IPPROTO_TCP && src_id != 0 &&
	    !is_geneve_tcp_client_syn(ip, data_end))
		return TC_ACT_OK;

	return enforce_flow(skb, ip, data_end, packet_bytes, now_ns, src_port, dst_port,
			    src_id, dst_id, is_geneve ? TC_ACT_STOLEN : TC_ACT_SHOT);
}

char _license[] SEC("license") = "GPL";
