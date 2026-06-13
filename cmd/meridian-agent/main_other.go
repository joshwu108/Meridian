//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"meridian-agent requires Linux (eBPF). On macOS, run inside the Lima VM: limactl shell meridian")
	os.Exit(1)
}
