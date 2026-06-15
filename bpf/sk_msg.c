// SPDX-License-Identifier: GPL-2.0
/*
 * sk_msg.c — Phase-2 SOCKHASH redirect fast path (MER-50 / ADR-0007).
 *
 * On sendmsg, redirect the message to the destination peer socket in `sockhash`
 * via bpf_msg_redirect_hash() with BPF_F_INGRESS (the peer receives on its
 * ingress queue). On a miss the message falls through to the normal kernel TCP
 * path (ADR-0007 fall-through contract).
 *
 * sk_msg is the SOLE READER of `sockhash`; it never inserts, repairs, or broadens
 * it — write authority stays in sock_ops (MER-48). Because sock_ops only inserts
 * ALLOW + SOCKMAP_ELIGIBLE sockets (CC-5, locked by the armed MER-49 gate), a hit
 * can never redirect a flow that required mTLS / L7 / proxy / deny handling.
 *
 * Why redirect directly instead of peeking: a bpf_map_lookup_elem() on a SOCKHASH
 * returns a ref-counted socket the verifier requires us to release, and the
 * release/acquire balance across the hit/miss branches is exactly what the
 * verifier rejected ("unreleased reference"). bpf_msg_redirect_hash() performs
 * its OWN internal lookup and arms the redirect only on a hit — returning SK_PASS
 * (redirect armed) on hit and SK_DROP (nothing armed) on miss. We translate that
 * miss-time SK_DROP into SK_PASS so a member socket sending to a peer that is not
 * in sockhash still follows the normal path. No socket reference is ever held.
 *
 * Key correspondence: sock_ops stored each socket under its OWN local (ip,port) —
 *   sock_key{ dst_ip = local_ip4 (net), dst_port = htons(local_port) }.
 * From the sender the destination is that peer's local address, exposed as
 * msg->remote_ip4 (network order) and msg->remote_port (network order, held in
 * the UPPER 16 bits on little-endian, same convention as bpf_sock_ops), so the
 * network-order 16-bit port is (u16)(remote_port >> 16) — the exact value
 * sock_ops wrote via bpf_htons(local_port).
 *
 * Telemetry (D13, bounded): a successful redirect bumps METRIC_FLOWS_REDIRECTED
 * (a per-CPU, lock-free counter) only — NOT a ring flow_event per sendmsg, which
 * would be per-message volume. A latency-stamped redirect flow_event needs
 * send->recv correlation that does not exist yet and is deferred to the
 * observability phase (O-3/O-4); it is deliberately not added here.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "meridian_helpers.h" /* AF_INET + maps/types/consts */

/* metrics_map is a PERCPU_ARRAY of __u64 counters (mirror of tc_*'s metric_add). */
static __always_inline void metric_add(__u32 id, __u64 delta)
{
	__u64 *val = bpf_map_lookup_elem(&metrics_map, &id);

	if (val)
		__sync_fetch_and_add(val, delta);
}

SEC("sk_msg")
int meridian_sk_msg(struct sk_msg_md *msg)
{
	if (msg->family != AF_INET)
		return SK_PASS;

	struct sock_key key = {
		.dst_ip = msg->remote_ip4,                   /* network order */
		.dst_port = (__u16)(msg->remote_port >> 16), /* network order (upper 16 on LE) */
		.pad = 0,
	};

	/* Hit -> helper arms the redirect and returns SK_PASS. Miss -> SK_DROP with
	 * nothing armed; we fall through to the normal kernel path (ADR-0007). */
	if (bpf_msg_redirect_hash(msg, &sockhash, &key, BPF_F_INGRESS) != SK_PASS)
		return SK_PASS;

	metric_add(METRIC_FLOWS_REDIRECTED, 1);
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
