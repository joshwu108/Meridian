// SPDX-License-Identifier: GPL-2.0
/*
 * meridian_types.h — Cross-boundary structs and enums shared between the
 * eBPF data plane and userspace. This header is the SINGLE SOURCE OF TRUTH
 * for any type that crosses the kernel/userspace boundary.
 *
 * The Go mirror of `struct flow_event` is generated EXCLUSIVELY by bpf2go
 * (`-type flow_event`). Never hand-write the Go wire layout.
 *
 * Depends only on vmlinux.h (BTF-derived __u8/__u16/__u32/__u64).
 */
#ifndef MERIDIAN_TYPES_H
#define MERIDIAN_TYPES_H

#include "vmlinux.h"

/*
 * MERIDIAN_SCHEMA_VERSION is written to schema_sentinel_map at load time and
 * read by userspace to fail closed on a layout mismatch between a loaded
 * object and the consuming agent. Bump on ANY change to a cross-boundary
 * struct or map add/remove.
 *
 * Defined as an enum (not #define) and used as the sentinel map's value type
 * so it lands in the object's BTF and bpf2go exports it to Go — the Go side
 * must never hand-mirror this number (CC-6 / review D-1).
 *
 * v1: Phase 0 (flow_event, metrics, sentinel).
 * v2: Phase 1 contract freeze (MER-14) — adds policy_key/policy_verdict/
 *     flow_key/deny_info and identity/policy/denied_flows maps; policy_key
 *     pad byte becomes direction (ADR-0003). v1 pins are refused (D15).
 */
enum meridian_schema_version {
	MERIDIAN_SCHEMA_VERSION = 2,
};

/*
 * struct flow_event — FROZEN canonical 56-byte layout (Phase 0 freeze).
 *
 * Byte offsets are load-bearing and must remain byte-identical between this
 * C definition and the bpf2go-generated Go mirror. All padding fields MUST be
 * explicitly zeroed by the producer so the bytes are deterministic (the ring
 * buffer hands raw memory to userspace; uninitialised pad bytes leak stack).
 *
 *   off  size  field
 *     0     8  timestamp_ns      CLOCK_MONOTONIC-since-boot (bpf_ktime_get_ns)
 *     8     4  src_ip            network byte order
 *    12     4  dst_ip            network byte order
 *    16     2  src_port          network byte order
 *    18     2  dst_port          network byte order
 *    20     1  proto             IPPROTO_TCP=6 / IPPROTO_UDP=17 / other
 *    21     1  verdict           enum flow_verdict
 *    22     2  _pad0
 *    24     4  src_identity      host byte order (numeric SPIFFE id; 0=unknown)
 *    28     4  dst_identity      host byte order
 *    32     4  bytes             host byte order (packet/payload size)
 *    36     4  _pad1
 *    40     8  latency_ns        host byte order (SOCKMAP send->recv; 0 if n/a)
 *    48     2  l7_status_code    host byte order (0 if not an L7 event)
 *    50     6  _pad2[3]          -> total 56 bytes, 8-byte aligned
 */
struct flow_event {
	__u64 timestamp_ns;   /*  0 */
	__u32 src_ip;         /*  8 */
	__u32 dst_ip;         /* 12 */
	__u16 src_port;       /* 16 */
	__u16 dst_port;       /* 18 */
	__u8  proto;          /* 20 */
	__u8  verdict;        /* 21 */
	__u16 _pad0;          /* 22 */
	__u32 src_identity;   /* 24 */
	__u32 dst_identity;   /* 28 */
	__u32 bytes;          /* 32 */
	__u32 _pad1;          /* 36 */
	__u64 latency_ns;     /* 40 */
	__u16 l7_status_code; /* 48 */
	__u16 _pad2[3];       /* 50..55 */
};

/*
 * Compile-time guard: if anything perturbs the layout, the build breaks here
 * rather than silently corrupting every decoded event in userspace.
 */
_Static_assert(sizeof(struct flow_event) == 56,
	       "flow_event must be exactly 56 bytes (frozen wire layout)");

/* Verdict values for flow_event.verdict. */
enum flow_verdict {
	FLOW_VERDICT_ALLOW    = 0,
	FLOW_VERDICT_DENY     = 1,
	FLOW_VERDICT_REDIRECT = 2,
};

/* Traffic direction for policy_key.direction (ADR-0003 / D12). */
enum policy_direction {
	POLICY_DIR_INGRESS = 0,
	POLICY_DIR_EGRESS  = 1,
};

/*
 * struct policy_key — exact-match key of policy_map. FROZEN v2 layout.
 *
 * Byte-order rule (ARCHITECTURE §2): identity IDs and dst_port are HOST
 * order — the BPF program parses the port with bpf_ntohs before lookup, and
 * the agent writes host-order values. direction replaces v1's zero pad
 * (same 12-byte size); it MUST be a valid enum policy_direction value —
 * HASH compares full key bytes, so a stray value is a silent lookup miss.
 *
 *   off  size  field
 *     0     4  src_id        host order (0 = unknown identity)
 *     4     4  dst_id        host order
 *     8     2  dst_port      host order
 *    10     1  proto         IPPROTO_TCP / IPPROTO_UDP
 *    11     1  direction     enum policy_direction
 */
struct policy_key {
	__u32 src_id;
	__u32 dst_id;
	__u16 dst_port;
	__u8  proto;
	__u8  direction;
};

_Static_assert(sizeof(struct policy_key) == 12,
	       "policy_key must be exactly 12 bytes (frozen v2 layout)");

/*
 * struct policy_verdict — value of policy_map. FROZEN v2 layout.
 *
 * action: enum flow_verdict (3-state). flags: orthogonal booleans per D4 —
 * bit 0 SOCKMAP_ELIGIBLE, bit 1 L7_REQUIRED, bit 2 MTLS_REQUIRED,
 * bit 3 AUDIT; bits 4–7 reserved, must be 0. _pad must be zeroed by the
 * writer (the agent zero-initializes the struct before population).
 */
struct policy_verdict {
	__u8  action;  /* enum flow_verdict */
	__u8  flags;   /* D4 bit layout */
	__u16 _pad;
};

_Static_assert(sizeof(struct policy_verdict) == 4,
	       "policy_verdict must be exactly 4 bytes (frozen v2 layout)");

/* policy_verdict.flags bits (D4). Bits 4-7 reserved, must be 0. */
#define POLICY_FLAG_SOCKMAP_ELIGIBLE (1 << 0)
#define POLICY_FLAG_L7_REQUIRED      (1 << 1)
#define POLICY_FLAG_MTLS_REQUIRED    (1 << 2)
#define POLICY_FLAG_AUDIT            (1 << 3)

/*
 * struct flow_key — key of denied_flows_map. FROZEN v2 layout.
 *
 * All address/port fields are NETWORK order (copied verbatim from packet
 * bytes, per the ARCHITECTURE §2 byte-order rule). Pads must be zeroed by
 * the producer — HASH compares full key bytes.
 *
 *   off  size  field
 *     0     4  src_ip        network order
 *     4     4  dst_ip        network order
 *     8     2  src_port      network order
 *    10     2  dst_port      network order
 *    12     1  proto
 *    13     3  _pad[3]
 */
struct flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  proto;
	__u8  _pad[3];
};

_Static_assert(sizeof(struct flow_key) == 16,
	       "flow_key must be exactly 16 bytes (frozen v2 layout)");

/*
 * struct deny_info — value of denied_flows_map (D14). FROZEN v2 layout.
 * Debug/observability surface only — never policy input.
 *
 *   off  size  field
 *     0     8  last_ns       bpf_ktime_get_ns of the most recent drop
 *     8     4  count         drops for this flow_key since LRU insertion
 *    12     4  reason        enum drop_reason
 */
struct deny_info {
	__u64 last_ns;
	__u32 count;
	__u32 reason;
};

_Static_assert(sizeof(struct deny_info) == 16,
	       "deny_info must be exactly 16 bytes (frozen v2 layout)");

/*
 * drop_reason — why a flow was denied. Filling reserved values is a
 * compatible change (no schema bump) per the ARCHITECTURE versioning rule;
 * MER-17 assigns the producer side.
 */
enum drop_reason {
	DROP_REASON_UNSPECIFIED      = 0,
	DROP_REASON_POLICY_DENY      = 1, /* explicit DENY verdict */
	DROP_REASON_POLICY_MISS      = 2, /* no policy_map entry (default-deny) */
	DROP_REASON_UNKNOWN_IDENTITY = 3, /* identity miss under default-deny posture */
	DROP_REASON_INVALID_ACTION   = 4, /* unrecognized action: fail closed */
	DROP_REASON_GENEVE_ENCAP_FAIL = 5, /* egress identity TLV stamp failure */
};

/*
 * metric_id — index space for metrics_map (PERCPU_ARRAY of __u64).
 *
 * The array is sized to METRIC_ID_MAX so the v1 metric set can grow WITHOUT
 * resizing the map (resizing would invalidate pins and break agent restart).
 * Reserved slots below METRIC_ID_MAX are zero-initialised and inert until a
 * later phase assigns them. Phase 0 only uses the first two.
 */
enum metric_id {
	METRIC_PACKETS_TOTAL    = 0, /* every packet seen by counter.c */
	METRIC_RINGBUF_DROPPED  = 1, /* kernel-side bpf_ringbuf_reserve failures */

	/* --- reserved for v1 (Phase 1+); do not renumber the two above --- */
	METRIC_BYTES_TOTAL      = 2,
	METRIC_FLOWS_ALLOWED    = 3,
	METRIC_FLOWS_DENIED     = 4,
	METRIC_FLOWS_REDIRECTED = 5,
	METRIC_GENEVE_ENCAP_FAIL = 6, /* egress identity TLV stamp failure (MER-20) */
	METRIC_GENEVE_DECODE_FAIL = 7, /* ingress identity TLV missing/undecodable (MER-21) */
	/* 8..15 reserved */

	METRIC_ID_MAX           = 16,
};

#endif /* MERIDIAN_TYPES_H */
