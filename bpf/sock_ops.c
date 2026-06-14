// SPDX-License-Identifier: GPL-2.0
/*
 * sock_ops.c — Phase-2 SOCKHASH population skeleton (MER-47 / ADR-0007).
 *
 * SCOPE (MER-47): contract skeleton ONLY. This program sits at the sock_ops
 * hook and currently performs NO sockhash insertion and NO policy lookup — it
 * returns 0 for every callback, leaving the shared `sockhash` map untouched.
 *
 * The gated population lands in MER-48: on ACTIVE/PASSIVE_ESTABLISHED, resolve
 * the flow's policy_key, look up policy_map, and call bpf_sock_hash_update()
 * ONLY when the verdict carries POLICY_FLAG_SOCKMAP_ELIGIBLE — the CC-5
 * gated-insertion invariant and the bypass point guarded by MER-49. Keeping
 * this a no-op skeleton freezes the program surface (SEC name, object/binding
 * names, the shared sockhash map) that MER-48/49/57/58 build against, without
 * yet introducing any SOCKMAP redirect/bypass behavior.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "meridian_maps.h"

SEC("sockops")
int meridian_sock_ops(struct bpf_sock_ops *ctx)
{
	/* MER-47 skeleton: gated SOCKHASH population is MER-48. Return 0 (OK)
	 * for all sock_ops callbacks; do not touch `sockhash`. */
	(void)ctx;
	return 0;
}

char _license[] SEC("license") = "GPL";
