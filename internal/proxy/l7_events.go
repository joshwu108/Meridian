package proxy

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/joshuawu/meridian/pkg/wire"
)

// L7Event is one observed HTTP request at the inbound proxy (P5.3), streamed
// to the admin server's /http/watch endpoint.
type L7Event struct {
	Time        time.Time       `json:"time"`
	SrcIdentity wire.IdentityID `json:"src_identity"`
	DstIdentity wire.IdentityID `json:"dst_identity"`
	DstPort     uint16          `json:"dst_port"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Verdict     string          `json:"verdict"` // "allow" | "deny"
}

// l7EventBuffer is the per-subscriber channel depth; subscribers that fall
// further behind lose events.
const l7EventBuffer = 64

// L7EventRing fans out JSON-encoded L7 events to subscribers. Publish never
// blocks the data path: slow subscribers drop events. A nil ring is a no-op.
type L7EventRing struct {
	mu   sync.Mutex
	subs []chan string
}

// NewL7EventRing returns an empty ring.
func NewL7EventRing() *L7EventRing {
	return &L7EventRing{}
}

// Subscribe registers a new subscriber; the channel receives one JSON line
// per event.
func (r *L7EventRing) Subscribe() <-chan string {
	ch := make(chan string, l7EventBuffer)
	r.mu.Lock()
	r.subs = append(r.subs, ch)
	r.mu.Unlock()
	return ch
}

// Publish JSON-encodes ev and delivers it to every subscriber without
// blocking.
func (r *L7EventRing) Publish(ev L7Event) {
	if r == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
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
