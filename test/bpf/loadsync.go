//go:build bpf

package bpftest

import "sync"

// bpfLoadMu serializes collection loads that pin maps under bpffs. Parallel
// test functions otherwise raced on per-run pin directory creation (MER-18).
var bpfLoadMu sync.Mutex
