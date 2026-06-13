package metrics

// MetricID indexes metrics_map slots in bpf/include/meridian_types.h.
type MetricID uint32

const (
	MetricPacketsTotal     MetricID = 0
	MetricRingbufDropped   MetricID = 1
	MetricBytesTotal       MetricID = 2
	MetricFlowsAllowed     MetricID = 3
	MetricFlowsDenied      MetricID = 4
	MetricFlowsRedirected  MetricID = 5
	MetricGeneveEncapFail  MetricID = 6
	MetricGeneveDecodeFail MetricID = 7

	MetricIDMax MetricID = 16
)

// Definition is one exported metrics_map counter.
type Definition struct {
	ID             MetricID
	PrometheusName string
	Help           string
}

var exportedMetrics = []Definition{
	{
		ID:             MetricPacketsTotal,
		PrometheusName: "meridian_packets_total",
		Help:           "Total packets observed by the eBPF dataplane.",
	},
	{
		ID:             MetricRingbufDropped,
		PrometheusName: "meridian_ringbuf_dropped_total",
		Help:           "Kernel-side bpf_ringbuf_reserve failures while emitting flow events.",
	},
	{
		ID:             MetricBytesTotal,
		PrometheusName: "meridian_bytes_total",
		Help:           "Total bytes observed by the eBPF dataplane.",
	},
	{
		ID:             MetricFlowsAllowed,
		PrometheusName: "meridian_flows_allowed_total",
		Help:           "Total flow decisions with ALLOW verdict.",
	},
	{
		ID:             MetricFlowsDenied,
		PrometheusName: "meridian_flows_denied_total",
		Help:           "Total flow decisions with DENY verdict.",
	},
	{
		ID:             MetricFlowsRedirected,
		PrometheusName: "meridian_flows_redirected_total",
		Help:           "Total flow decisions with REDIRECT verdict.",
	},
	{
		ID:             MetricGeneveEncapFail,
		PrometheusName: "meridian_geneve_encap_fail_total",
		Help:           "Total Geneve egress identity option stamp failures.",
	},
	{
		ID:             MetricGeneveDecodeFail,
		PrometheusName: "meridian_geneve_decode_fail_total",
		Help:           "Total Geneve ingress flows whose identity option was missing or undecodable.",
	},
}

var metricByID = func() map[MetricID]Definition {
	out := make(map[MetricID]Definition, len(exportedMetrics))
	for _, m := range exportedMetrics {
		out[m.ID] = m
	}
	return out
}()

// Reader resolves one metrics_map slot to its per-CPU aggregate.
type Reader interface {
	Read(MetricID) (uint64, error)
}

// Exported returns the metric definitions exported through Prometheus.
func Exported() []Definition {
	out := make([]Definition, len(exportedMetrics))
	copy(out, exportedMetrics)
	return out
}

// Lookup returns the metric definition for id.
func Lookup(id MetricID) (Definition, bool) {
	m, ok := metricByID[id]
	return m, ok
}
