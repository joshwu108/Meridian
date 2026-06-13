// Package integration holds Phase 0 T3 (netns) tests: a real veth pair, real
// traffic, and assertions on the kernel-side PERCPU counter plus the Go
// ring-buffer consumer end to end.
//
// The tests are behind the `integration` build tag and require root:
//
//	make test-integration
//
// This untagged file keeps the package visible to the toolchain on hosts
// where the tag (or OS) excludes the test files.
package integration
