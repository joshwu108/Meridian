package proxy

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/joshuawu/meridian/pkg/wire"
)

// L7Event is one observed HTTP request at the inbound proxy (P5.3). Events
// feed the agent admin server's /http/watch stream (meridian http watch).
type L7Event struct {
	Time        time.Time       `json:"time"`
	SrcIdentity wire.IdentityID `json:"src_identity"`
	DstIdentity wire.IdentityID `json:"dst_identity"`
	DstPort     uint16          `json:"dst_port"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Verdict     string          `json:"verdict"` // "allow" | "deny"
}

// l7EventBuffer is the per-subscriber channel depth. A subscriber that falls
// further behind loses events (drop, never block the data path).
const l7EventBuffer = 64

// L7EventRing fans out JSON-encoded L7 events to subscribers. Publishing
// never blocks: slow subscribers drop events. A nil ring is a no-op, so the
// inbound handler can call Publish unconditionally.
type L7EventRing struct {
	mu   sync.Mutex
	subs []chan string
}

// NewL7EventRing returns an empty ring.
func NewL7EventRing() *L7EventRing {
	return &L7EventRing{}
}

// Subscribe registers a new subscriber and returns its event channel.
// The channel receives one JSON line per event. It satisfies the agent admin
// server's event-source interface (Subscribe() <-chan string).
func (r *L7EventRing) Subscribe() <-chan string {
	ch := make(chan string, l7EventBuffer)
	r.mu.Lock()
	r.subs = append(r.subs, ch)
	r.mu.Unlock()
	return ch
}

// Publish JSON-encodes ev and delivers it to every subscriber without
// blocking. Nil-safe.
func (r *L7EventRing) Publish(ev L7Event) {
	if r == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return // struct of scalars: cannot fail, but never panic the data path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.subs {
		select {
		case ch <- string(line):
		default: // subscriber full: drop
		}
	}
}
