package telemetry

import (
	"container/list"
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/joshuawu/meridian/internal/agent/identitytable"
	"github.com/joshuawu/meridian/pkg/wire"
)

const (
	// DefaultPairCapacity bounds the number of distinct (src,dst) identity
	// aggregates retained in memory and therefore the number of exported label
	// pairs. When full, the least recently seen pair is evicted (LRU).
	DefaultPairCapacity = 1024
	unknownLabelValue   = "unknown"
)

type flowKey struct {
	src uint32
	dst uint32
}

// Aggregate is the current counter state for one (src,dst) identity pair.
type Aggregate struct {
	SrcIdentity uint32
	DstIdentity uint32
	AllowCount  uint64
	DenyCount   uint64
	ByteCount   uint64
}

type aggregateEntry struct {
	key   flowKey
	value Aggregate
}

// Aggregator consumes decoded flow events and keeps bounded per-pair counters.
//
// It is concurrency-safe: Handle and Snapshot can be called concurrently.
type Aggregator struct {
	mu       sync.RWMutex
	capacity int
	entries  map[flowKey]*list.Element
	lru      *list.List
}

// NewAggregator builds a bounded aggregator.
func NewAggregator(capacity int) *Aggregator {
	if capacity <= 0 {
		capacity = DefaultPairCapacity
	}
	return &Aggregator{
		capacity: capacity,
		entries:  make(map[flowKey]*list.Element, capacity),
		lru:      list.New(),
	}
}

// Handle implements telemetry.Handler.
func (a *Aggregator) Handle(event Event) {
	if a == nil {
		return
	}

	key := flowKey{
		src: event.SrcIdentity,
		dst: event.DstIdentity,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	element, ok := a.entries[key]
	if !ok {
		if len(a.entries) >= a.capacity {
			a.evictOldest()
		}
		entry := &aggregateEntry{
			key: key,
			value: Aggregate{
				SrcIdentity: event.SrcIdentity,
				DstIdentity: event.DstIdentity,
			},
		}
		element = a.lru.PushFront(entry)
		a.entries[key] = element
	} else {
		a.lru.MoveToFront(element)
	}

	entry := element.Value.(*aggregateEntry)
	switch event.Verdict {
	case VerdictAllow:
		entry.value.AllowCount++
	case VerdictDeny:
		entry.value.DenyCount++
	}
	entry.value.ByteCount += uint64(event.Bytes)
}

// Snapshot returns a stable copy of all current pair aggregates.
func (a *Aggregator) Snapshot() []Aggregate {
	if a == nil {
		return nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Aggregate, 0, len(a.entries))
	for _, element := range a.entries {
		entry := element.Value.(*aggregateEntry)
		out = append(out, entry.value)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SrcIdentity != out[j].SrcIdentity {
			return out[i].SrcIdentity < out[j].SrcIdentity
		}
		return out[i].DstIdentity < out[j].DstIdentity
	})
	return out
}

// Size returns the currently tracked distinct (src,dst) key count.
func (a *Aggregator) Size() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

func (a *Aggregator) evictOldest() {
	oldest := a.lru.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*aggregateEntry)
	delete(a.entries, entry.key)
	a.lru.Remove(oldest)
}

type aggregateCollector struct {
	aggregator *Aggregator
	resolver   identitytable.Resolver
	allowDesc  *prometheus.Desc
	denyDesc   *prometheus.Desc
	bytesDesc  *prometheus.Desc
}

// NewAggregateCollector exposes bounded pair aggregates as labeled metrics.
//
// Labels use SPIFFE names resolved through resolver. Missing, unresolved, or
// empty names are emitted as "unknown" (never empty).
func NewAggregateCollector(aggregator *Aggregator, resolver identitytable.Resolver) prometheus.Collector {
	return &aggregateCollector{
		aggregator: aggregator,
		resolver:   resolver,
		allowDesc: prometheus.NewDesc(
			"meridian_flow_allow_total",
			"Total ALLOW verdicts per source/destination identity pair.",
			[]string{"src_identity", "dst_identity"},
			nil,
		),
		denyDesc: prometheus.NewDesc(
			"meridian_flow_deny_total",
			"Total DENY verdicts per source/destination identity pair.",
			[]string{"src_identity", "dst_identity"},
			nil,
		),
		bytesDesc: prometheus.NewDesc(
			"meridian_flow_bytes_total",
			"Total bytes per source/destination identity pair.",
			[]string{"src_identity", "dst_identity"},
			nil,
		),
	}
}

func (c *aggregateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.allowDesc
	ch <- c.denyDesc
	ch <- c.bytesDesc
}

func (c *aggregateCollector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.aggregator == nil {
		return
	}
	aggregates := c.aggregator.Snapshot()
	type labelKey struct {
		src string
		dst string
	}
	type aggregateValue struct {
		allow uint64
		deny  uint64
		bytes uint64
	}

	// Multiple numeric identity pairs can collapse to the same resolved label
	// pair (for example unresolved IDs map to "unknown"). Merge before export so
	// each metric family emits a unique labelset.
	merged := make(map[labelKey]aggregateValue, len(aggregates))
	for _, aggregate := range aggregates {
		srcLabel := c.resolveLabel(aggregate.SrcIdentity)
		dstLabel := c.resolveLabel(aggregate.DstIdentity)
		key := labelKey{
			src: srcLabel,
			dst: dstLabel,
		}
		value := merged[key]
		value.allow += aggregate.AllowCount
		value.deny += aggregate.DenyCount
		value.bytes += aggregate.ByteCount
		merged[key] = value
	}

	for key, value := range merged {
		ch <- prometheus.MustNewConstMetric(
			c.allowDesc,
			prometheus.CounterValue,
			float64(value.allow),
			key.src,
			key.dst,
		)
		ch <- prometheus.MustNewConstMetric(
			c.denyDesc,
			prometheus.CounterValue,
			float64(value.deny),
			key.src,
			key.dst,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc,
			prometheus.CounterValue,
			float64(value.bytes),
			key.src,
			key.dst,
		)
	}
}

func (c *aggregateCollector) resolveLabel(rawID uint32) string {
	if c == nil || c.resolver == nil {
		return unknownLabelValue
	}

	identity, ok, err := c.resolver.Resolve(context.Background(), wire.IdentityID(rawID))
	if err != nil || !ok {
		return unknownLabelValue
	}
	if strings.TrimSpace(identity.SpiffeID) == "" {
		return unknownLabelValue
	}
	return identity.SpiffeID
}
