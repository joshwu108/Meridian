package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestProxyMetricsRegisterAndRecord(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewProxyMetrics(reg)

	m.RecordRequest("inbound", "allow", "1", "2", 10*time.Millisecond)
	m.RecordRequest("inbound", "deny", "3", "4", 1*time.Millisecond)
	m.RecordRequest("outbound", "allow", "5", "6", 5*time.Millisecond)

	expected := `
# HELP meridian_proxy_requests_total Total proxy requests by direction, verdict and identity pair.
# TYPE meridian_proxy_requests_total counter
meridian_proxy_requests_total{direction="inbound",dst_identity="2",src_identity="1",status="allow"} 1
meridian_proxy_requests_total{direction="inbound",dst_identity="4",src_identity="3",status="deny"} 1
meridian_proxy_requests_total{direction="outbound",dst_identity="6",src_identity="5",status="allow"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"meridian_proxy_requests_total"); err != nil {
		t.Fatalf("metrics mismatch: %v", err)
	}
}

func TestProxyMetricsCBState(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewProxyMetrics(reg)

	m.UpdateCBState("10.0.0.1", CBClosed)
	m.UpdateCBState("10.0.0.2", CBOpen)

	expected := `
# HELP meridian_proxy_circuit_breaker_state Circuit breaker state: 0=closed 1=open 2=half-open.
# TYPE meridian_proxy_circuit_breaker_state gauge
meridian_proxy_circuit_breaker_state{upstream="10.0.0.1"} 0
meridian_proxy_circuit_breaker_state{upstream="10.0.0.2"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"meridian_proxy_circuit_breaker_state"); err != nil {
		t.Fatalf("CB state mismatch: %v", err)
	}
}

func TestProxyMetricsNilSafe(t *testing.T) {
	var m *ProxyMetrics
	// Must not panic.
	m.RecordRequest("inbound", "allow", "1", "2", time.Second)
	m.UpdateCBState("upstream", CBOpen)
}
