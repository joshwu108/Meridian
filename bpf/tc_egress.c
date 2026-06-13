// SPDX-License-Identifier: GPL-2.0
/*
 * tc_egress.c — Geneve egress identity propagation (MER-20).
 *
 * Verifier notes:
 *   - Every packet dereference is guarded by data_end bounds checks.
 *   - Geneve option walk is hard-capped at MERIDIAN_MAX_GENEVE_OPTS with
 *     #pragma unroll (no unbounded loops).
 *   - Pointer revalidation happens after each computed offset.
 *   - Encapsulation failure behavior follows ADR-0005:
 *       * always increment METRIC_GENEVE_ENCAP_FAIL
 *       * fail-closed by default (TC_ACT_SHOT + deny telemetry)
 *       * fail-open only when MERIDIAN_CFG_FALLOPEN_UNKNOWN is set
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "meridian_consts.h"
#include "meridian_maps.h"
#include "meridian_types.h"

static __always_inline __u32 failopen_unknown_enabled(void)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&runtime_config_map, &key);

	if (!cfg)
		return 0;
	return (*cfg & MERIDIAN_CFG_FALLOPEN_UNKNOWN) != 0;
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

static __always_inline __u32 parse_l4_ports(struct iphdr *ip, void *data_end,
					    __u16 *src_port, __u16 *dst_port)
{
	__u32 ihl = ip->ihl;

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

static __always_inline __u32 looks_like_ipv4(void *ptr, void *data_end)
{
	struct iphdr *ip = ptr;

	if ((void *)(ip + 1) > data_end)
		return 0;
	return ip->version == 4 && ip->ihl >= IPV4_IHL_MIN && ip->ihl <= IPV4_IHL_MAX;
}

static __always_inline __u32 parse_geneve_option_count(void *opts, void *data_end,
							__u32 opt_bytes, __u32 *count_out)
{
	__u32 offset = 0;
	__u32 count = 0;

	for (int i = 0; i < 4; i++) {
		__u8 *opt;
		__u32 opt_len_words;
		__u32 opt_size;

		if (offset == opt_bytes) {
			*count_out = count;
			return 1;
		}
		if (offset > opt_bytes)
			return 0;

		opt = opts + offset;
		if (opt + 4 > (__u8 *)data_end)
			return 0;

		opt_len_words = opt[3] & 0x1f;
		opt_size = 4 + (opt_len_words * 4);
		if (opt_size < 4)
			return 0;
		offset += opt_size;
		count++;
	}

	if (offset != opt_bytes)
		return 0;
	*count_out = count;
	return 1;
}

SEC("tc")
int meridian_tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 packet_bytes = skb->len;
	__u64 now_ns = bpf_ktime_get_ns();

	struct flow_key flow = {};
	__u32 has_flow = 0;
	__u32 event_src_id = 0;
	__u32 event_dst_id = 0;

	/* Parse outer Ethernet + IPv4 + UDP Geneve. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *outer_ip = (void *)(eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		return TC_ACT_OK;
	if (outer_ip->version != 4 || outer_ip->ihl < IPV4_IHL_MIN ||
	    outer_ip->ihl > IPV4_IHL_MAX)
		return TC_ACT_OK;
	if (outer_ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	struct udphdr *udp = (void *)outer_ip + outer_ip->ihl * IPV4_WORD_BYTES;
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;
	if (udp->dest != bpf_htons(MERIDIAN_GENEVE_UDP_PORT))
		return TC_ACT_OK;

	/* Geneve base header (8 bytes) starts after UDP. */
	__u8 *geneve = (void *)(udp + 1);
	if (geneve + 8 > (__u8 *)data_end)
		goto encap_fail;

	/* Version must be 0 for Geneve v0. */
	if ((geneve[0] >> 6) != 0)
		goto encap_fail;

	__u32 opt_words = geneve[0] & 0x3f;
	__u32 opt_bytes = opt_words * 4;
	if (opt_words > MERIDIAN_MAX_GENEVE_OPT_WORDS)
		goto encap_fail;

	__u8 *opts = geneve + 8;
	if (opts + opt_bytes > (__u8 *)data_end)
		goto encap_fail;

	__u32 option_count = 0;
	if (!parse_geneve_option_count(opts, data_end, opt_bytes, &option_count))
		goto encap_fail;

	/*
	 * Headroom model:
	 *   - no reserved room: inner IP starts at opts+opt_bytes
	 *   - reserved room:    inner IP starts at opts+opt_bytes+8
	 * This keeps parsing verifier-simple and deterministic.
	 */
	__u8 *inner_base = opts + opt_bytes;
	struct iphdr *inner_ip = 0;
	__u32 reserved_headroom = 0;
	if (looks_like_ipv4(inner_base, data_end)) {
		inner_ip = (void *)inner_base;
		reserved_headroom = 0;
	} else if (looks_like_ipv4(inner_base + MERIDIAN_GENEVE_OPT_BYTES, data_end)) {
		inner_ip = (void *)(inner_base + MERIDIAN_GENEVE_OPT_BYTES);
		reserved_headroom = MERIDIAN_GENEVE_OPT_BYTES;
	} else {
		goto encap_fail;
	}

	__u16 src_port = 0;
	__u16 dst_port = 0;
	if (!parse_l4_ports(inner_ip, data_end, &src_port, &dst_port))
		goto encap_fail;

	flow.src_ip = inner_ip->saddr;
	flow.dst_ip = inner_ip->daddr;
	flow.src_port = src_port;
	flow.dst_port = dst_port;
	flow.proto = inner_ip->protocol;
	flow._pad[0] = 0;
	flow._pad[1] = 0;
	flow._pad[2] = 0;
	has_flow = 1;

	__u32 src_key = inner_ip->saddr;
	__u32 dst_key = inner_ip->daddr;
	__u32 *src_identity = bpf_map_lookup_elem(&identity_map, &src_key);
	__u32 *dst_identity = bpf_map_lookup_elem(&identity_map, &dst_key);
	if (dst_identity)
		event_dst_id = *dst_identity;

	if (!src_identity || *src_identity == 0)
		goto encap_fail;
	event_src_id = *src_identity;

	if (option_count >= MERIDIAN_MAX_GENEVE_OPTS)
		goto encap_fail;
	if (reserved_headroom != MERIDIAN_GENEVE_OPT_BYTES)
		goto encap_fail;

	/* Construct Meridian identity TLV in the reserved headroom slot. */
	__u8 *new_opt = inner_base;
	if (new_opt + MERIDIAN_GENEVE_OPT_BYTES > (__u8 *)data_end)
		goto encap_fail;

	__u16 class_be = bpf_htons(MERIDIAN_GENEVE_CLASS);
	__u32 src_id_be = bpf_htonl(event_src_id);
	__builtin_memcpy(&new_opt[0], &class_be, sizeof(class_be));
	new_opt[2] = MERIDIAN_OPT_IDENTITY;
	new_opt[3] = MERIDIAN_GENEVE_IDENTITY_LEN_WORDS;
	__builtin_memcpy(&new_opt[4], &src_id_be, sizeof(src_id_be));

	geneve[0] = (geneve[0] & 0xc0) | (opt_words + MERIDIAN_GENEVE_OPT_WORDS);
	return TC_ACT_OK;

encap_fail:
	metric_add(METRIC_GENEVE_ENCAP_FAIL, 1);
	if (failopen_unknown_enabled())
		return TC_ACT_OK;

	if (has_flow) {
		denied_flow_upsert(&flow, DROP_REASON_GENEVE_ENCAP_FAIL, now_ns);
		metric_add(METRIC_FLOWS_DENIED, 1);
		emit_flow_event(now_ns, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
				flow.proto, FLOW_VERDICT_DENY, event_src_id, event_dst_id, packet_bytes);
	}
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
