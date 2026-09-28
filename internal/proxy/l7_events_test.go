package proxy

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestL7EventRingFanOut(t *testing.T) {
	ring := NewL7EventRing()
	sub1 := ring.Subscribe()
	sub2 := ring.Subscribe()

	ev := L7Event{
		Time:        time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		SrcIdentity: wire.IdentityID(7),
		DstIdentity: wire.IdentityID(9),
		DstPort:     8080,
		Method:      "GET",
		Path:        "/api/users",
		Verdict:     "allow",
	}
	ring.Publish(ev)

	for i, sub := range []<-chan string{sub1, sub2} {
		select {
		case line := <-sub:
			var got L7Event
			if err := json.Unmarshal([]byte(line), &got); err != nil {
				t.Fatalf("sub%d: event is not valid JSON: %v (%q)", i+1, err, line)
			}
			if got.Method != "GET" || got.Path != "/api/users" || got.Verdict != "allow" {
				t.Fatalf("sub%d: got %+v, want published event", i+1, got)
			}
			if got.SrcIdentity != 7 || got.DstIdentity != 9 || got.DstPort != 8080 {
				t.Fatalf("sub%d: identity fields = %+v, want src=7 dst=9 port=8080", i+1, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("sub%d: no event within timeout", i+1)
		}
	}
}

func TestL7EventRingSlowSubscriberDropsNotBlocks(t *testing.T) {
	ring := NewL7EventRing()
	_ = ring.Subscribe() // never drained

	// Publishing more events than the channel buffer must not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < l7EventBuffer+10; i++ {
			ring.Publish(L7Event{Method: "GET", Path: "/x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
}

func TestL7EventRingNilSafe(t *testing.T) {
	var ring *L7EventRing
	ring.Publish(L7Event{Method: "GET"})
}

// TestPublishL7Event verifies the inbound handler's event emission: a parsed
// request produces one event with the verdict mapped from the policy action,
// and nil request / nil ring are no-ops.
func TestPublishL7Event(t *testing.T) {
	ring := NewL7EventRing()
	sub := ring.Subscribe()
	h := &InboundHandler{l7Events: ring}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"POST /admin/config HTTP/1.1\r\nHost: svc\r\n\r\n")))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	h.publishL7Event(req, wire.IdentityID(3), wire.IdentityID(4), 443, wire.PolicyActionDeny)
	select {
	case line := <-sub:
		var got L7Event
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Method != "POST" || got.Path != "/admin/config" || got.Verdict != "deny" {
			t.Fatalf("event = %+v, want POST /admin/config deny", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published")
	}

	// nil request (non-HTTP stream) and nil ring must both be no-ops.
	h.publishL7Event(nil, 0, 0, 0, wire.PolicyActionAllow)
	select {
	case line := <-sub:
		t.Fatalf("unexpected event for nil request: %q", line)
	default:
	}
	(&InboundHandler{}).publishL7Event(req, 0, 0, 0, wire.PolicyActionAllow)
}
