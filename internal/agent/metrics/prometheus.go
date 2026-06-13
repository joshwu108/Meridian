package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type collector struct {
	reader Reader
	descs  map[MetricID]*prometheus.Desc
}

// NewCollector exposes metrics_map counters to Prometheus.
func NewCollector(reader Reader) prometheus.Collector {
	descs := make(map[MetricID]*prometheus.Desc, len(exportedMetrics))
	for _, metric := range exportedMetrics {
		descs[metric.ID] = prometheus.NewDesc(metric.PrometheusName, metric.Help, nil, nil)
	}
	return &collector{
		reader: reader,
		descs:  descs,
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.descs {
		ch <- desc
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	for _, metric := range exportedMetrics {
		value, err := c.reader.Read(metric.ID)
		if err != nil {
			ch <- prometheus.NewInvalidMetric(c.descs[metric.ID], err)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descs[metric.ID], prometheus.CounterValue, float64(value))
	}
}

// NewRegistry returns a registry containing only Meridian map metrics.
func NewRegistry(reader Reader) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(reader))
	return reg
}

// NewServer returns an HTTP server that exposes GET /metrics.
func NewServer(addr string, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
}

// Shutdown closes the metrics server gracefully.
func Shutdown(server *http.Server) error {
	if server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
