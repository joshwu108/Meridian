// SPDX-License-Identifier: GPL-2.0
/*
 * meridian_parse.h — shared L2/L3 parse helpers for tc_ingress / tc_egress.
 *
 * MER-43: unwrap a single 802.1Q tag and return the inner IPv4 header when
 * present. Non-IPv4 outer/inner ethertypes and truncated tags pass through
 * (caller returns TC_ACT_OK).
 */
#ifndef MERIDIAN_PARSE_H
#define MERIDIAN_PARSE_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>

#include "meridian_consts.h"

static __always_inline __u32 looks_like_ipv4(void *ptr, void *data_end)
{
	struct iphdr *ip = ptr;

	if ((void *)(ip + 1) > data_end)
		return 0;
	return ip->version == 4 && ip->ihl >= IPV4_IHL_MIN && ip->ihl <= IPV4_IHL_MAX;
}

/*
 * parse_ipv4_after_eth locates an IPv4 header immediately after the Ethernet
 * header, or after one 802.1Q tag. Returns 0 when the frame should passthrough.
 */
static __always_inline __u32 parse_ipv4_after_eth(struct ethhdr *eth, void *data_end,
						  struct iphdr **ip_out)
{
	void *l3;

	if ((void *)(eth + 1) > data_end)
		return 0;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		l3 = (void *)(eth + 1);
	} else if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
		__u8 *vlan = (void *)(eth + 1);

		if (vlan + VLAN_INNER_HDR_BYTES > (__u8 *)data_end)
			return 0;
		if (*(__be16 *)(vlan + 2) != bpf_htons(ETH_P_IP))
			return 0;
		l3 = vlan + VLAN_INNER_HDR_BYTES;
	} else {
		return 0;
	}

	if (!looks_like_ipv4(l3, data_end))
		return 0;

	*ip_out = l3;
	return 1;
}

/*
 * parse_ipv4_in_geneve_payload locates the inner IPv4 header carried inside a
 * Geneve frame. Test packets use proto 0x0800 with either a pre-reserved TLV
 * slot (MERIDIAN_GENEVE_OPT_BYTES before the inner IP) or none. The kernel
 * geneve driver uses proto ETH_P_TEB (0x6558) with an inner Ethernet header
 * (MER-28 / ADR-0002 live path).
 */
static __always_inline __u32 parse_ipv4_in_geneve_payload(void *payload, void *data_end,
							  struct iphdr **ip_out,
							  __u32 *reserved_tlv_bytes_out)
{
	*reserved_tlv_bytes_out = 0;

	if (looks_like_ipv4(payload + MERIDIAN_GENEVE_OPT_BYTES, data_end)) {
		*ip_out = payload + MERIDIAN_GENEVE_OPT_BYTES;
		*reserved_tlv_bytes_out = MERIDIAN_GENEVE_OPT_BYTES;
		return 1;
	}
	if (looks_like_ipv4(payload, data_end)) {
		*ip_out = payload;
		return 1;
	}
	return parse_ipv4_after_eth(payload, data_end, ip_out);
}

#endif /* MERIDIAN_PARSE_H */
