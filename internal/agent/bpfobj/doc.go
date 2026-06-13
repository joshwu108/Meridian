// Package bpfobj is the SOLE opener of Meridian's BPF objects and pinned
// state. It owns the load-or-reopen discipline: on a fresh node it creates
// and pins maps; on agent restart it re-opens existing pins (never
// re-creates), preserving live kernel state and in-flight connections.
//
// No other package may call ebpf.LoadPinnedMap / LoadAndAssign against
// Meridian pin paths; everyone else receives already-opened handles from
// here (import rule enforced by package boundaries; see docs/ARCHITECTURE.md).
//
// The loader implementation is Linux-only (loader_linux.go); this file keeps
// the package buildable on non-Linux development hosts.
package bpfobj
