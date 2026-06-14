// SPDX-License-Identifier: GPL-2.0
/*
 * sock_ops.c — Phase-2 gated SOCKHASH population (MER-48 / ADR-0007).
 *
 * On TCP established (active or passive), the program resolves the flow's
 * compiled policy_verdict and inserts the socket into the shared `sockhash`
 * map ONLY when that verdict is a plain-L4 ALLOW carrying
 * POLICY_FLAG_SOCKMAP_ELIGIBLE — the CC-5 gated-insertion invariant. Every
 * other verdict class (DENY, REDIRECT, ALLOW+L7_REQUIRED, ALLOW+MTLS_REQUIRED,
 * ALLOW without the flag), and any unknown identity, policy miss, or non-IPv4
 * family, leaves `sockhash` untouched. This map write is ROADMAP Top-risk #2 /
 * eBPF R2: a wrongly inserted socket is exactly what would let sk_msg (MER-50)
 * later bypass mTLS, L7 policy, redirect, or deny.
 *
 * Byte order (bpf_sock_ops, 5.15 UAPI): local_ip4/remote_ip4 are network order;
 * local_port is host order (low 16 bits); remote_port is network order but the
 * kernel left-shifts it into the UPPER 16 bits on little-endian, so the port is
 * `bpf_ntohs(remote_port >> 16)`. identity_map is keyed by the network-order
 * IPv4. policy_key.dst_port is host order; sock_key.dst_port is network order.
 *
 * The ACTIVE/PASSIVE_ESTABLISHED callbacks fire unconditionally for sockets in
 * the attached cgroup on 5.15 — no bpf_sock_ops_cb_flags_set opt-in is needed
 * for them (that flag gates the optional state/retransmit callbacks we do not
 * use). The exhaustive negative matrix is the permanent gate MER-49 (P2.1-N).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "meridian_consts.h"
#include "meridian_types.h"
#include "meridian_maps.h"
#include "meridian_helpers.h"

/*
 * try_insert — insert THIS socket under its own local (dst_ip, dst_port) so a
 * peer redirecting toward it (sk_msg, MER-50) finds it. Gated on the CC-5
 * eligibility check; a no-op for any ineligible or unknown-identity flow.
 */
static __always_inline void try_insert(struct bpf_sock_ops *ctx,
				       __u32 src_id, __u32 dst_id,
				       __u16 dst_port_host, __u8 direction)
{
	/* Unknown identity on either end: fail closed, never insert (CC-5). */
	if (src_id == 0 || dst_id == 0)
		return;

	struct policy_verdict *v = meridian_policy_lookup(src_id, dst_id,
							  dst_port_host,
							  IPPROTO_TCP, direction);
	if (!meridian_verdict_sockmap_eligible(v))
		return;

	struct sock_key key = {
		.dst_ip = ctx->local_ip4,                  /* network order */
		.dst_port = bpf_htons((__u16)ctx->local_port), /* host -> network */
		.pad = 0,
	};

	bpf_sock_hash_update(ctx, &sockhash, &key, BPF_ANY);
}

SEC("sockops")
int meridian_sock_ops(struct bpf_sock_ops *ctx)
{
	if (ctx->family != AF_INET)
		return 0;

	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
		/* We initiated the connection: egress. src=local, dst=remote;
		 * the service port is the remote port (network order). */
		__u32 src_id = meridian_identity_of(ctx->local_ip4);
		__u32 dst_id = meridian_identity_of(ctx->remote_ip4);
		__u16 dport = bpf_ntohs((__u16)(ctx->remote_port >> 16));

		try_insert(ctx, src_id, dst_id, dport, POLICY_DIR_EGRESS);
		break;
	}
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		/* We accepted the connection: ingress. src=remote, dst=local;
		 * the service port is our local listen port (host order). */
		__u32 src_id = meridian_identity_of(ctx->remote_ip4);
		__u32 dst_id = meridian_identity_of(ctx->local_ip4);
		__u16 dport = (__u16)ctx->local_port;

		try_insert(ctx, src_id, dst_id, dport, POLICY_DIR_INGRESS);
		break;
	}
	default:
		break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
