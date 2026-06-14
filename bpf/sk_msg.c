// SPDX-License-Identifier: GPL-2.0
/*
 * sk_msg.c — Phase-2 SOCKMAP redirect skeleton (MER-47 / ADR-0007).
 *
 * SCOPE (MER-47): contract skeleton ONLY. Attached with BPF_SK_MSG_VERDICT to
 * the shared `sockhash` map, this program currently performs NO sockhash lookup
 * and NO redirect — it returns SK_PASS for every message so the normal kernel
 * TCP path is unchanged.
 *
 * The redirect path lands in MER-50: look up the peer socket in `sockhash` by
 * sock_key and, on hit, call bpf_msg_redirect_map(); on miss return SK_PASS so
 * the normal kernel path continues (ADR-0007 fall-through contract). sk_msg is
 * the SOLE reader of `sockhash` and never inserts, repairs, or broadens it —
 * write authority stays in sock_ops. Keeping this a no-op skeleton freezes the
 * program surface (SEC name, object/binding names) that MER-50/57/58 build
 * against, without yet introducing any redirect/bypass behavior.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "meridian_maps.h"

SEC("sk_msg")
int meridian_sk_msg(struct sk_msg_md *ctx)
{
	/* MER-47 skeleton: the sockhash lookup + bpf_msg_redirect_map() hit path
	 * is MER-50. SK_PASS keeps the message on the normal kernel path. */
	(void)ctx;
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
