// SPDX-License-Identifier: GPL-2.0
/*
 * counter.c — toolchain/verifier smoke artifact (not in the production datapath).
 *
 * Purpose: validate the end-to-end telemetry pipeline (TC hook -> PERCPU
 * counter -> ring buffer -> Go consumer) on the 5.15 target. It parses
 * Ethernet + IPv4 (+ TCP/UDP ports when present), bumps METRIC_PACKETS_TOTAL,
 * and emits ONE flow_event PER PACKET, then always returns TC_ACT_OK.
 *
 * This program remains intentionally simple and per-packet so CI can quickly
 * detect toolchain/verifier regressions independent of MER-17 policy logic.
 *
 * Verifier discipline (must stay clean on 5.15): every packet dereference is
 * bounds-checked against data_end before use; the IHL-derived L4 offset is
 * range-clamped so the verifier can prove the access.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "meridian_types.h"
#include "meridian_consts.h"
#include "meridian_maps.h"

static __always_inline void metric_inc(__u32 id)
{
	__u64 *val = bpf_map_lookup_elem(&metrics_map, &id);
	if (val)
		__sync_fetch_and_add(val, 1);
}

SEC("tc")
int meridian_counter(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* Every packet counts, regardless of protocol. */
	metric_inc(METRIC_PACKETS_TOTAL);

	/* L2: Ethernet header. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Phase 0 parses IPv4 only; everything else passes through unparsed. */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* L3: IPv4 header (minimum 20 bytes; options handled via ihl below). */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Clamp ihl so the verifier can bound the L4 offset. */
	__u32 ihl = ip->ihl;
	if (ihl < IPV4_IHL_MIN || ihl > IPV4_IHL_MAX)
		return TC_ACT_OK;
	__u32 ip_hdr_bytes = ihl * IPV4_WORD_BYTES;

	__u8  proto  = ip->protocol;
	__u32 src_ip = ip->saddr;   /* network order */
	__u32 dst_ip = ip->daddr;   /* network order */

	/* L4: read src/dst ports for TCP and UDP only. Both place the 16-bit
	 * source and destination ports in the first 4 bytes of their header,
	 * so a single bounds-checked read covers both. */
	__u16 src_port = 0;
	__u16 dst_port = 0;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		void *l4 = (void *)ip + ip_hdr_bytes;
		if (l4 + L4_PORTS_BYTES <= data_end) {
			__be16 *ports = l4;
			src_port = ports[0];   /* network order, kept as-is */
			dst_port = ports[1];
		}
	}

	/*
	 * Emit one flow_event. Reserve can fail when the ring is full; count
	 * that as a kernel-side drop and continue — never block the packet.
	 */
	struct flow_event *ev =
		bpf_ringbuf_reserve(&flow_events, sizeof(*ev), 0);
	if (!ev) {
		metric_inc(METRIC_RINGBUF_DROPPED);
		return TC_ACT_OK;
	}

	/* Fill every field; zero all pads so the wire bytes are deterministic. */
	ev->timestamp_ns   = bpf_ktime_get_ns();  /* CLOCK_MONOTONIC since boot */
	ev->src_ip         = src_ip;
	ev->dst_ip         = dst_ip;
	ev->src_port       = src_port;
	ev->dst_port       = dst_port;
	ev->proto          = proto;
	ev->verdict        = FLOW_VERDICT_ALLOW;   /* Phase 0: always ALLOW */
	ev->_pad0          = 0;
	ev->src_identity   = 0;                     /* Phase 0: no identity map */
	ev->dst_identity   = 0;
	ev->bytes          = skb->len;
	ev->_pad1          = 0;
	ev->latency_ns     = 0;                     /* no SOCKMAP in Phase 0 */
	ev->l7_status_code = 0;                     /* not an L7 event */
	ev->_pad2[0]       = 0;
	ev->_pad2[1]       = 0;
	ev->_pad2[2]       = 0;

	bpf_ringbuf_submit(ev, 0);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
