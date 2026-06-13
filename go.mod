module github.com/joshuawu/meridian

go 1.22

// Active dependency set (minimal — grow per phase; see PRD §13 for pinned
// targets). Phase 1 adds vishvananda/netlink for production TC attachment.
require (
	github.com/cilium/ebpf v0.17.3
	github.com/prometheus/client_golang v1.20.0
	github.com/vishvananda/netlink v1.3.0
	golang.org/x/sys v0.30.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Pinned targets for later phases (PRD §13) — added by the phase that first
// imports them; do not add ahead of need:
//   google.golang.org/grpc v1.70.0                         // P3 ADS stream
//   github.com/envoyproxy/go-control-plane v0.13.4         // P3 xDS types
//   github.com/spiffe/go-spiffe/v2 v2.3.0                  // P4 Workload API, SVID
//   go.opentelemetry.io/otel v1.28.0 (+ otlptrace)         // P5 traces
//   github.com/prometheus/client_golang v1.20.0            // P1 metrics
//   github.com/go-chi/chi/v5 v5.2.5                        // P3 REST / admin
//   go.etcd.io/etcd/client/v3                              // P7 storage backend
//   k8s.io/client-go                                       // P7 informers
