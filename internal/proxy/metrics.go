package proxy

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ProxyMetrics holds the Prometheus metrics for the node proxy (P5.3).
// Register with a prometheus.Registerer; the agent shares its :9901 registry.
type ProxyMetrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	CBState        *prometheus.GaugeVec
}

// NewProxyMetrics creates and registers the proxy metrics with reg.
func NewProxyMetrics(reg prometheus.Registerer) *ProxyMetrics {
	factory := promauto.With(reg)
	return &ProxyMetrics{
		RequestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "meridian_proxy_requests_total",
			Help: "Total proxy requests by direction, verdict and identity pair.",
		}, []string{"direction", "status", "src_identity", "dst_identity"}),

		RequestLatency: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "meridian_proxy_request_duration_seconds",
			Help:    "Proxy request duration (dial + stream) in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		}, []string{"direction"}),

		CBState: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "meridian_proxy_circuit_breaker_state",
			Help: "Circuit breaker state: 0=closed 1=open 2=half-open.",
		}, []string{"upstream"}),
	}
}

// RecordRequest records one proxy request with its duration and status.
// direction is "inbound" or "outbound"; status is "allow", "deny", or "error".
func (m *ProxyMetrics) RecordRequest(direction, status, srcID, dstID string, dur time.Duration) {
	if m == nil {
		return
	}
	m.RequestsTotal.WithLabelValues(direction, status, srcID, dstID).Inc()
	m.RequestLatency.WithLabelValues(direction).Observe(dur.Seconds())
}

// UpdateCBState reports the circuit breaker state for a given upstream address.
func (m *ProxyMetrics) UpdateCBState(upstream string, state CBState) {
	if m == nil {
		return
	}
	m.CBState.WithLabelValues(upstream).Set(float64(state))
}
