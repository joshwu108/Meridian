//go:build linux

package metrics

import (
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeReader struct {
	values map[MetricID]uint64
}

func (f fakeReader) Read(id MetricID) (uint64, error) {
	return f.values[id], nil
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name string
		id   MetricID
		want string
		ok   bool
	}{
		{
			name: "known packets metric",
			id:   MetricPacketsTotal,
			want: "meridian_packets_total",
			ok:   true,
		},
		{
			name: "known denied metric",
			id:   MetricFlowsDenied,
			want: "meridian_flows_denied_total",
			ok:   true,
		},
		{
			name: "unknown metric id",
			id:   MetricIDMax + 1,
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, ok := Lookup(tt.id)
			if ok != tt.ok {
				t.Fatalf("Lookup(%d) ok=%v, want %v", tt.id, ok, tt.ok)
			}
			if tt.ok && def.PrometheusName != tt.want {
				t.Fatalf("Lookup(%d) name=%q, want %q", tt.id, def.PrometheusName, tt.want)
			}
		})
	}
}

func TestCollectorWithFakeReader(t *testing.T) {
	reg := NewRegistry(fakeReader{
		values: map[MetricID]uint64{
			MetricPacketsTotal:    11,
			MetricRingbufDropped:  2,
			MetricBytesTotal:      4096,
			MetricFlowsAllowed:    7,
			MetricFlowsDenied:     3,
			MetricFlowsRedirected: 1,
		},
	})

	expected := `
# HELP meridian_packets_total Total packets observed by the eBPF dataplane.
# TYPE meridian_packets_total counter
meridian_packets_total 11
# HELP meridian_ringbuf_dropped_total Kernel-side bpf_ringbuf_reserve failures while emitting flow events.
# TYPE meridian_ringbuf_dropped_total counter
meridian_ringbuf_dropped_total 2
# HELP meridian_bytes_total Total bytes observed by the eBPF dataplane.
# TYPE meridian_bytes_total counter
meridian_bytes_total 4096
# HELP meridian_flows_allowed_total Total flow decisions with ALLOW verdict.
# TYPE meridian_flows_allowed_total counter
meridian_flows_allowed_total 7
# HELP meridian_flows_denied_total Total flow decisions with DENY verdict.
# TYPE meridian_flows_denied_total counter
meridian_flows_denied_total 3
# HELP meridian_flows_redirected_total Total flow decisions with REDIRECT verdict.
# TYPE meridian_flows_redirected_total counter
meridian_flows_redirected_total 1
`

	if err := testutil.GatherAndCompare(
		reg,
		strings.NewReader(expected),
		"meridian_packets_total",
		"meridian_ringbuf_dropped_total",
		"meridian_bytes_total",
		"meridian_flows_allowed_total",
		"meridian_flows_denied_total",
		"meridian_flows_redirected_total",
	); err != nil {
		t.Fatalf("gather and compare: %v", err)
	}
}

func TestMapReaderLiveMap(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "test_metrics_map",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(MetricIDMax),
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	perCPU := make([]uint64, runtime.NumCPU())
	perCPU[0] = 3
	if len(perCPU) > 1 {
		perCPU[1] = 5
	}
	if len(perCPU) > 2 {
		perCPU[2] = 7
	}

	if err := m.Put(uint32(MetricPacketsTotal), perCPU); err != nil {
		t.Fatalf("put metric value: %v", err)
	}

	reader := NewMapReader(m)
	got, err := reader.Read(MetricPacketsTotal)
	if err != nil {
		t.Fatalf("read metric: %v", err)
	}

	var want uint64
	for _, v := range perCPU {
		want += v
	}
	if got != want {
		t.Fatalf("sum = %d, want %d", got, want)
	}
}

func TestMapReaderRejectsOutOfRangeID(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "test_metrics_map_bounds",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(MetricIDMax),
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	reader := NewMapReader(m)
	_, err = reader.Read(MetricIDMax)
	if err == nil {
		t.Fatal("expected out-of-range read to fail")
	}
}

func TestMetricsEndpointFunctional(t *testing.T) {
	reg := NewRegistry(fakeReader{
		values: map[MetricID]uint64{
			MetricPacketsTotal: 99,
		},
	})
	server := NewServer("127.0.0.1:0", reg)
	t.Cleanup(func() {
		_ = Shutdown(server)
	})

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ln)
	}()

	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("get /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(body), "meridian_packets_total 99") {
		t.Fatalf("response does not contain expected counter; body=%q", string(body))
	}

	if err := Shutdown(server); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve returned error: %v", err)
	}
}

func TestAggregatePerCPU(t *testing.T) {
	tests := []struct {
		name   string
		values []uint64
		want   uint64
	}{
		{
			name:   "empty slice",
			values: nil,
			want:   0,
		},
		{
			name:   "single cpu",
			values: []uint64{9},
			want:   9,
		},
		{
			name:   "multiple cpus",
			values: []uint64{1, 2, 3, 4},
			want:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aggregatePerCPU(tt.values); got != tt.want {
				t.Fatalf("aggregatePerCPU(%v) = %d, want %d", tt.values, got, tt.want)
			}
		})
	}
}
