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
#define TC_ACT_STOLEN     4
#define TC_ACT_REDIRECT   7

/* Ethertypes (compared against eth->h_proto in network order via bpf_htons). */
#define ETH_P_IP     0x0800   /* IPv4 */
#define ETH_P_8021Q  0x8100   /* 802.1Q VLAN (MER-43: unwrap inner L3) */
#define ETH_P_TEB    0x6558   /* Transparent Ethernet Bridging (kernel Geneve) */
#define ETH_P_IPV6   0x86DD   /* IPv6 (Phase 0: passthrough, not parsed) */

/* 802.1Q tag after ethhdr: TCI (2) + inner ethertype (2). TPID is eth->h_proto. */
#define VLAN_INNER_HDR_BYTES 4

/* L4 protocol numbers (ip->protocol). */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Ring buffer size: 4 MiB. Power of two — enforced by the RINGBUF map type. */
#define MERIDIAN_RINGBUF_BYTES (4u * 1024u * 1024u)

/* Map sizing (ARCHITECTURE §2, frozen v2). */
#define MERIDIAN_IDENTITY_MAP_ENTRIES 65536
#define MERIDIAN_POLICY_MAP_ENTRIES   16384
#define MERIDIAN_DENIED_FLOWS_ENTRIES 4096
#define MERIDIAN_UDP_SEEN_FLOWS_ENTRIES 4096
#define MERIDIAN_SOCKHASH_ENTRIES     65536 /* ADR-0007 SOCKHASH (Phase 2) */

/* runtime_config_map[0] bit flags (D16). Unset bits = fail-closed defaults. */
#define MERIDIAN_CFG_FALLOPEN_UNKNOWN (1u << 0)

/* Geneve transport + Meridian identity option (ADR-0002 / ADR-0005). */
#define MERIDIAN_GENEVE_UDP_PORT 6081
#define MERIDIAN_GENEVE_CLASS    0x4d52 /* "MR" */
#define MERIDIAN_OPT_IDENTITY    1

/* Geneve option sizing: identity option is 8 bytes total (4-byte hdr + u32 body). */
#define MERIDIAN_GENEVE_OPT_BYTES          8
#define MERIDIAN_GENEVE_OPT_WORDS          2 /* 8 bytes / 4-byte Geneve units */
#define MERIDIAN_GENEVE_IDENTITY_LEN_WORDS 1 /* body length in 4-byte units */
#define MERIDIAN_MAX_GENEVE_OPTS           4
#define MERIDIAN_MAX_GENEVE_OPT_WORDS      (MERIDIAN_MAX_GENEVE_OPTS * MERIDIAN_GENEVE_OPT_WORDS)

/*
 * Redirect placeholder mark (MER-17): REDIRECT verdict marks skb but does not
 * perform a tc redirect action yet.
 */
#define MERIDIAN_MARK_REDIRECT_PLACEHOLDER (1u << 0)

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
