// SPDX-License-Identifier: GPL-2.0
/*
 * meridian_consts.h — local constants for Meridian BPF programs.
 *
 * We deliberately DEFINE TC return codes and protocol/ethertype constants
 * locally rather than pulling <linux/pkt_cls.h> / <linux/if_ether.h> uapi
 * headers, so the BPF objects build CO-RE-style against vmlinux.h alone
 * (BTF) with no dependency on a kernel-headers package on the build host.
 * Values match the kernel UAPI and are ABI-stable.
 */
#ifndef MERIDIAN_CONSTS_H
#define MERIDIAN_CONSTS_H

/* TC action return codes (uapi/linux/pkt_cls.h). */
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK         0
#define TC_ACT_SHOT       2
#define TC_ACT_REDIRECT   7

/* Ethertypes (compared against eth->h_proto in network order via bpf_htons). */
#define ETH_P_IP   0x0800   /* IPv4 */
#define ETH_P_IPV6 0x86DD   /* IPv6 (Phase 0: passthrough, not parsed) */

/* L4 protocol numbers (ip->protocol). */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Ring buffer size: 4 MiB. Power of two — enforced by the RINGBUF map type. */
#define MERIDIAN_RINGBUF_BYTES (4u * 1024u * 1024u)

/* Map sizing (ARCHITECTURE §2, frozen v2). */
#define MERIDIAN_IDENTITY_MAP_ENTRIES 65536
#define MERIDIAN_POLICY_MAP_ENTRIES   16384
#define MERIDIAN_DENIED_FLOWS_ENTRIES 4096

/* runtime_config_map[0] bit flags (D16). Unset bits = fail-closed defaults. */
#define MERIDIAN_CFG_FALLOPEN_UNKNOWN (1u << 0)

/*
 * BPF_F_NO_PREALLOC (uapi/linux/bpf.h, ABI-stable). vmlinux.h usually carries
 * the kernel's anonymous enum with this value; the guard makes the header
 * self-sufficient if a given BTF dump omits it.
 */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

/*
 * Bounds constants for the IPv4 parser.
 * IHL is a 4-bit field counting 32-bit words: header length = ihl * 4 bytes.
 * A valid IPv4 header is 20..60 bytes (ihl 5..15).
 */
#define IPV4_IHL_MIN        5     /* 20 bytes, no options */
#define IPV4_IHL_MAX        15    /* 60 bytes, max options */
#define IPV4_WORD_BYTES     4
#define L4_PORTS_BYTES      4     /* src(2) + dst(2): common TCP/UDP prefix */

#endif /* MERIDIAN_CONSTS_H */
