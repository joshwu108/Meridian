// SPDX-License-Identifier: GPL-2.0
/*
 * tc_ingress.c — Phase 1 production ingress parser + identity resolution.
 *
 * Scope in MER-16:
 *   - Verifier-safe Ethernet / IPv4 / TCP / UDP parsing with explicit bounds checks.
 *   - src/dst identity lookups from identity_map (key = IPv4 BE bytes as loaded).
 *   - Unknown-identity posture toggle:
 *       * fail-closed (default) -> TC_ACT_SHOT
 *       * fail-open             -> TC_ACT_OK
 *   - Non-IPv4 passthrough -> TC_ACT_OK.
 *
 * Policy evaluation and decision-point telemetry emission land in MER-17.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "meridian_consts.h"
#include "meridian_types.h"

/* identity_map: pod IPv4 (network bytes, as loaded) -> identity id (host). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} identity_map SEC(".maps");

/*
 * runtime_config_map[0] bit flags.
 * bit 0 set => fail-open unknown identities.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} runtime_config_map SEC(".maps");

#define CFG_FALLOPEN_UNKNOWN_BIT (1u << 0)

static __always_inline __u32 failopen_unknown_enabled(void)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&runtime_config_map, &key);

	/* Default is fail-closed unless the operator explicitly enables fail-open. */
	if (!cfg)
		return 0;
	return (*cfg & CFG_FALLOPEN_UNKNOWN_BIT) != 0;
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

SEC("tc")
int meridian_tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

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

	if (!src_identity || !dst_identity || *src_identity == 0 || *dst_identity == 0) {
		if (failopen_unknown_enabled())
			return TC_ACT_OK;
		return TC_ACT_SHOT;
	}

	/* MER-16 stops at parser + identity posture; policy lookup lands in MER-17. */
	(void)src_port;
	(void)dst_port;
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
