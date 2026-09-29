package telemetry

import (
	"encoding/json"
	"sync"
	"time"
)

const (
	broadcasterBufSize  = 64 // per-subscriber channel buffer
	broadcasterMaxDrops = 8  // consecutive drops before a subscriber is pruned
)

// Broadcaster fans decoded flow events out to zero or more SSE subscribers.
// It implements admin.FlowSource via Subscribe and can be used as a
// telemetry.Handler via Handle.
//
// Subscribers that fall too far behind (broadcasterMaxDrops consecutive
// non-blocking send failures) are pruned — this handles HTTP clients that
// disconnected without an explicit Unsubscribe call.
type Broadcaster struct {
	mu   sync.Mutex
	subs []*subscriber
}

type subscriber struct {
	ch    chan string
	drops int
}

// Subscribe returns a channel that receives JSON-encoded flow event lines.
// The channel is buffered; events are dropped (not blocked on) when full.
// The channel is closed when the Broadcaster itself is no longer needed.
func (b *Broadcaster) Subscribe() <-chan string {
	ch := make(chan string, broadcasterBufSize)
	b.mu.Lock()
	b.subs = append(b.subs, &subscriber{ch: ch})
	b.mu.Unlock()
	return ch
}

// Handle encodes ev as a single JSON line and fans it out to all live subscribers.
func (b *Broadcaster) Handle(ev Event) {
	line := encodeLine(ev)
	b.mu.Lock()
	defer b.mu.Unlock()

	alive := b.subs[:0]
	for _, sub := range b.subs {
		select {
		case sub.ch <- line:
			sub.drops = 0
			alive = append(alive, sub)
		default:
			sub.drops++
			if sub.drops < broadcasterMaxDrops {
				alive = append(alive, sub)
			}
			// else: pruned — channel is left open, GC reclaims it
		}
	}
	b.subs = alive
}

// jsonEvent is the wire shape emitted to SSE subscribers.
type jsonEvent struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     uint8     `json:"proto"`
	Verdict   string    `json:"verdict"`
	Bytes     uint32    `json:"bytes"`
	SrcID     uint32    `json:"src_id"`
	DstID     uint32    `json:"dst_id"`
}

func verdictName(v Verdict) string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictDeny:
		return "deny"
	default:
		return "unknown"
	}
}

func encodeLine(ev Event) string {
	j := jsonEvent{
		Timestamp: ev.Timestamp,
		SrcIP:     ev.SrcIP.String(),
		DstIP:     ev.DstIP.String(),
		SrcPort:   ev.SrcPort,
		DstPort:   ev.DstPort,
		Proto:     ev.Proto,
		Verdict:   verdictName(ev.Verdict),
		Bytes:     ev.Bytes,
		SrcID:     ev.SrcIdentity,
		DstID:     ev.DstIdentity,
	}
	b, _ := json.Marshal(j)
	return string(b)
}
