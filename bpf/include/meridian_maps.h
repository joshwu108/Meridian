// SPDX-License-Identifier: GPL-2.0
/*
 * meridian_maps.h — BPF map definitions shared across Meridian programs.
 *
 * Every map is pinned LIBBPF_PIN_BY_NAME under the loader's pin path (the
 * agent loads with a pin root of /sys/fs/bpf/meridian/; tests use a per-run
 * subtree of /sys/fs/bpf/meridian-test/), so kernel map state survives an
 * agent restart and multiple programs share one instance.
 */
#ifndef MERIDIAN_MAPS_H
#define MERIDIAN_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "meridian_types.h"
#include "meridian_consts.h"

/*
 * flow_events — RINGBUF carrying struct flow_event records to the agent.
 * max_entries for RINGBUF is the byte size and MUST be a power of two
 * (kernel enforces this at load time).
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MERIDIAN_RINGBUF_BYTES);
	__type(value, struct flow_event);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_events SEC(".maps");

/*
 * metrics_map — PERCPU_ARRAY of __u64 counters indexed by enum metric_id.
 * Per-CPU so kernel increments are lock-free; userspace sums across CPUs on
 * scrape. Sized to METRIC_ID_MAX to allow the v1 metric set to grow in place.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, METRIC_ID_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics_map SEC(".maps");

/*
 * schema_sentinel_map — single-slot ARRAY holding MERIDIAN_SCHEMA_VERSION.
 * Written once by the agent loader (bpfobj) right after load; read on every
 * subsequent re-open so an agent built against a different schema fails
 * closed instead of misinterpreting pinned state.
 *
 * The value type is the schema enum (4 bytes, same wire size as __u32) so
 * the version constant reaches BTF and bpf2go exports it to Go (review D-1).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, enum meridian_schema_version);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} schema_sentinel_map SEC(".maps");

/*
 * identity_map — pod IPv4 (network order) → numeric identity (host order).
 * Agent (datapath.Writer) is the sole writer; tc_ingress/tc_egress and the
 * node proxy read. NO_PREALLOC: identities churn with pods; don't reserve
 * 65536 entries of kernel memory up front.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MERIDIAN_IDENTITY_MAP_ENTRIES);
	__type(key, __u32);   /* pod IPv4, network order */
	__type(value, __u32); /* identity ID, host order; 0 = unknown (never stored) */
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} identity_map SEC(".maps");

/*
 * policy_map — compiled exact-match L4 rules (ADR-0003 key incl. direction).
 * Agent (datapath.Writer) is the sole writer; miss = deny (default-deny,
 * PRD §8). sock_ops additionally reads it for the SOCKMAP_ELIGIBLE check
 * (CC-5) in Phase 2.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MERIDIAN_POLICY_MAP_ENTRIES);
	__type(key, struct policy_key);
	__type(value, struct policy_verdict);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

/*
 * runtime_config_map — single-slot ARRAY of runtime behavior flags
 * (MERIDIAN_CFG_* bits in meridian_consts.h). Agent writes, programs read
 * per packet. Phase 1 uses bit 0 = FALLOPEN_UNKNOWN (ADR-0001/D16):
 * unset (default) = fail closed on unknown identities.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} runtime_config_map SEC(".maps");

/*
 * denied_flows_map — recent drops for debugging/observability (D14); never
 * policy input. LRU so it self-evicts under flood (note: LRU_HASH must NOT
 * set BPF_F_NO_PREALLOC — the kernel rejects that combination).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MERIDIAN_DENIED_FLOWS_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct deny_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} denied_flows_map SEC(".maps");

#endif /* MERIDIAN_MAPS_H */
