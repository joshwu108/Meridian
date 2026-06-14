// SPDX-License-Identifier: GPL-2.0
/*
 * meridian_helpers.h — shared policy-resolution primitives for the socket-layer
 * programs (sock_ops, sk_msg).
 *
 * CC-6 single-source: identity resolution, the compiled-verdict lookup, and the
 * CC-5 SOCKMAP-eligibility predicate live here exactly once so MER-48 (sock_ops
 * gated population) and MER-50 (sk_msg redirect) cannot drift apart in how they
 * read identity_map / policy_map.
 *
 * The tc_ingress / tc_egress programs intentionally keep their own packet-context
 * enforcement (flow_event emission, denied_flows accounting, metrics) inline:
 * that path has skb side effects this header does not model. These helpers are
 * the L4 verdict *primitive* both layers agree on, not a re-home of tc logic.
 */
#ifndef MERIDIAN_HELPERS_H
#define MERIDIAN_HELPERS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "meridian_types.h"
#include "meridian_consts.h"
#include "meridian_maps.h"

/* AF_INET / BPF_ANY are ABI-stable; guard-define in case a BTF dump omits them. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

/*
 * meridian_identity_of — numeric identity for a pod IPv4 (network order, as the
 * kernel stores local_ip4/remote_ip4 and as identity_map is keyed). Returns 0
 * (unknown) on miss; callers treat 0 as fail-closed.
 */
static __always_inline __u32 meridian_identity_of(__u32 ipv4_net)
{
	__u32 *id = bpf_map_lookup_elem(&identity_map, &ipv4_net);

	return id ? *id : 0;
}

/*
 * meridian_policy_lookup — compiled policy_verdict for a directional L4 flow, or
 * NULL on miss (default-deny). dst_port is HOST order per the frozen policy_key
 * contract (ADR-0003 / meridian_types.h); direction is enum policy_direction.
 */
static __always_inline struct policy_verdict *
meridian_policy_lookup(__u32 src_id, __u32 dst_id, __u16 dst_port_host,
		       __u8 proto, __u8 direction)
{
	struct policy_key key = {
		.src_id = src_id,
		.dst_id = dst_id,
		.dst_port = dst_port_host,
		.proto = proto,
		.direction = direction,
	};

	return bpf_map_lookup_elem(&policy_map, &key);
}

/*
 * meridian_verdict_sockmap_eligible — the CC-5 gated-insertion invariant
 * (ADR-0007): a socket may enter SOCKHASH only when the compiled verdict is a
 * plain-L4 ALLOW carrying POLICY_FLAG_SOCKMAP_ELIGIBLE. DENY, REDIRECT, ALLOW
 * with L7/mTLS required, ALLOW without the flag, and policy miss (NULL) are all
 * ineligible. The kernel re-checks the flag here even though the compiler should
 * only ever set it for safe flows — the map write is the bypass point.
 * Returns 1 when eligible, 0 otherwise.
 */
static __always_inline int
meridian_verdict_sockmap_eligible(const struct policy_verdict *v)
{
	return v && v->action == FLOW_VERDICT_ALLOW &&
	       (v->flags & POLICY_FLAG_SOCKMAP_ELIGIBLE);
}

#endif /* MERIDIAN_HELPERS_H */
