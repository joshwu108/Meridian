//go:build bpf

package bpftest

import "sync"

// bpfLoadMu synchronizes BPF object loads for prog_test_run/attach tests that pin maps under bpffs.
var bpfLoadMu sync.Mutex
