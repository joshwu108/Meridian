package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestPeekAndMatchL7_HTTPAllow(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		{Method: "GET", PathPrefix: "/api/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
		{PathPrefix: "/admin/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny}},
	}
	req := "GET /api/users HTTP/1.1\r\nHost: svc\r\n\r\n"
	action, remainder := peekAndMatchL7(strings.NewReader(req), rules)
	if action != wire.PolicyActionAllow {
		t.Fatalf("want allow, got %v", action)
	}
	body, _ := io.ReadAll(remainder)
	if !bytes.Contains(body, []byte("GET")) {
		t.Fatalf("remainder must replay the request bytes, got: %q", body)
	}
}

func TestPeekAndMatchL7_HTTPDeny(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		{PathPrefix: "/admin/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny}},
	}
	req := "GET /admin/config HTTP/1.1\r\nHost: svc\r\n\r\n"
	action, _ := peekAndMatchL7(strings.NewReader(req), rules)
	if action != wire.PolicyActionDeny {
		t.Fatalf("want deny, got %v", action)
	}
}

func TestPeekAndMatchL7_NonHTTPPassthrough(t *testing.T) {
	// Binary data that is not HTTP — should allow (non-HTTP flow).
	data := "\x00\x01\x02\x03 not http"
	action, remainder := peekAndMatchL7(strings.NewReader(data), []wire.CompiledL7Rule{
		{PathPrefix: "/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny}},
	})
	if action != wire.PolicyActionAllow {
		t.Fatalf("non-HTTP should pass through: want allow, got %v", action)
	}
	_ = remainder
}

func TestPeekAndMatchL7_HTTP2Preface(t *testing.T) {
	h2preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	action, _ := peekAndMatchL7(strings.NewReader(h2preface), []wire.CompiledL7Rule{
		{PathPrefix: "/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny}},
	})
	// HTTP/2 passes through (framing deferred).
	if action != wire.PolicyActionAllow {
		t.Fatalf("HTTP/2 preface should pass through: want allow, got %v", action)
	}
}

func TestPeekAndMatchL7_EmptyStream(t *testing.T) {
	action, _ := peekAndMatchL7(bytes.NewReader(nil), nil)
	if action != wire.PolicyActionAllow {
		t.Fatalf("empty stream: want allow, got %v", action)
	}
}
