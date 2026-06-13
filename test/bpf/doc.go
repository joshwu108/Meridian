// Package bpftest holds Phase 0 T2 tests: programs exercised with the
// kernel's BPF_PROG_TEST_RUN facility (cilium/ebpf prog.Run) against
// synthetic packets. No network, no netns — just load, inject, assert.
//
// The tests are behind the `bpf` build tag and require root:
//
//	make test-bpf
//
// This untagged file keeps the package visible to the toolchain on hosts
// where the tag (or OS) excludes the test files.
package bpftest
