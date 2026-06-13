//go:build linux

package metrics

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// MapReader reads counters from the pinned metrics_map PERCPU_ARRAY.
type MapReader struct {
	m *ebpf.Map
}

func NewMapReader(m *ebpf.Map) *MapReader {
	return &MapReader{m: m}
}

// Read returns the summed value for one metric ID.
func (r *MapReader) Read(id MetricID) (uint64, error) {
	if r == nil || r.m == nil {
		return 0, fmt.Errorf("metrics: nil metrics map")
	}
	if id >= MetricIDMax {
		return 0, fmt.Errorf("metrics: metric id %d out of range", id)
	}

	var perCPU []uint64
	if err := r.m.Lookup(uint32(id), &perCPU); err != nil {
		return 0, err
	}
	return aggregatePerCPU(perCPU), nil
}

func aggregatePerCPU(values []uint64) uint64 {
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}
