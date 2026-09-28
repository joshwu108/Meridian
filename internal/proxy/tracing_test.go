package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/joshuawu/meridian/pkg/wire"
)

// TestNewTracerProviderNoopWithoutEndpoint verifies that without
// OTEL_EXPORTER_OTLP_ENDPOINT the provider is a no-op (spans not recorded),
// so existing behavior and tests are unchanged.
func TestNewTracerProviderNoopWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	tp, shutdown, err := NewTracerProvider(context.Background())
	if err != nil {
		t.Fatalf("NewTracerProvider: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	_, span := tp.Tracer("test").Start(context.Background(), "conn")
	defer span.End()
	if span.SpanContext().IsValid() {
		t.Fatal("no endpoint configured: expected no-op tracer (invalid span context)")
	}
}

// TestNewTracerProviderWithEndpoint verifies that a configured endpoint yields
// a real (recording) provider. No collector needs to be listening — the
// batcher only dials on export.
func TestNewTracerProviderWithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	tp, shutdown, err := NewTracerProvider(context.Background())
	if err != nil {
		t.Fatalf("NewTracerProvider: %v", err)
	}
	_, span := tp.Tracer("test").Start(context.Background(), "conn")
	if !span.SpanContext().IsValid() {
		t.Fatal("endpoint configured: expected recording tracer (valid span context)")
	}
	span.End()
	// Shutdown may fail to flush to the (absent) collector; only require that
	// it returns rather than hanging.
	_ = shutdown(context.Background())
}

func newRecordingTracer() (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	return rec, tp
}

// TestConnSpanAttributes verifies the per-connection span carries the required
// attributes: src_identity, dst_identity, dst_port, verdict, latency_ns.
func TestConnSpanAttributes(t *testing.T) {
	rec, tp := newRecordingTracer()
	tracer := tp.Tracer("meridian-proxy")

	_, cs := startConnSpan(context.Background(), tracer, "proxy.inbound")
	cs.end(wire.IdentityID(7), wire.IdentityID(9), 8080, "allow")

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	got := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		got[string(kv.Key)] = kv.Value.AsInterface()
	}
	if got["src_identity"] != int64(7) || got["dst_identity"] != int64(9) {
		t.Fatalf("identity attrs = %v, want src=7 dst=9", got)
	}
	if got["dst_port"] != int64(8080) {
		t.Fatalf("dst_port = %v, want 8080", got["dst_port"])
	}
	if got["verdict"] != "allow" {
		t.Fatalf("verdict = %v, want allow", got["verdict"])
	}
	latency, ok := got["latency_ns"].(int64)
	if !ok || latency < 0 {
		t.Fatalf("latency_ns = %v, want non-negative int64", got["latency_ns"])
	}
}

// TestConnSpanNilSafe verifies handlers can call span helpers unconditionally
// when tracing is disabled.
func TestConnSpanNilSafe(t *testing.T) {
	ctx, cs := startConnSpan(context.Background(), nil, "proxy.inbound")
	if ctx == nil {
		t.Fatal("context must pass through")
	}
	if cs != nil {
		t.Fatalf("nil tracer: connSpan = %v, want nil", cs)
	}
	cs.end(0, 0, 0, "deny") // must not panic
	if tp := cs.traceparent(); tp != "" {
		t.Fatalf("nil connSpan traceparent = %q, want empty", tp)
	}
}

// TestConnSpanTraceparentFormat verifies the W3C traceparent header format.
func TestConnSpanTraceparentFormat(t *testing.T) {
	_, tp := newRecordingTracer()
	_, cs := startConnSpan(context.Background(), tp.Tracer("t"), "proxy.outbound")
	defer cs.end(0, 0, 0, "allow")

	re := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
	if got := cs.traceparent(); !re.MatchString(got) {
		t.Fatalf("traceparent = %q, want W3C format 00-<traceid>-<spanid>-<flags>", got)
	}
}

// TestInjectTraceparentHTTP verifies the header is inserted after the HTTP/1.1
// request line and the rest of the stream is preserved byte-for-byte.
func TestInjectTraceparentHTTP(t *testing.T) {
	const tpHeader = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	in := "GET /api/users HTTP/1.1\r\nHost: svc\r\n\r\nbody-bytes"
	out, err := io.ReadAll(injectTraceparent(strings.NewReader(in), tpHeader))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := "GET /api/users HTTP/1.1\r\ntraceparent: " + tpHeader + "\r\nHost: svc\r\n\r\nbody-bytes"
	if string(out) != want {
		t.Fatalf("injected stream:\n%q\nwant:\n%q", out, want)
	}
}

// TestInjectTraceparentNonHTTPPassthrough verifies non-HTTP streams are not
// modified.
func TestInjectTraceparentNonHTTPPassthrough(t *testing.T) {
	in := []byte("\x00\x01\x02 binary protocol")
	out, err := io.ReadAll(injectTraceparent(bytes.NewReader(in), "00-x-x-01"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("non-HTTP stream modified: %q, want %q", out, in)
	}
}

// TestInjectTraceparentEmptyHeader verifies an empty traceparent leaves the
// stream untouched (tracing disabled path).
func TestInjectTraceparentEmptyHeader(t *testing.T) {
	in := []byte("GET / HTTP/1.1\r\n\r\n")
	out, err := io.ReadAll(injectTraceparent(bytes.NewReader(in), ""))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("stream modified with empty traceparent: %q", out)
	}
}

// TestOutboundHandlerTracing drives the outbound handler with a recording
// tracer and verifies (a) the traceparent header is injected into the HTTP
// stream seen by the upstream, and (b) a span with the connection attributes
// is recorded.
func TestOutboundHandlerTracing(t *testing.T) {
	rec, tp := newRecordingTracer()
	origDst := netip.MustParseAddrPort("10.0.0.5:8080")
	resolver := &fakeResolver{origDst: origDst, dstID: wire.IdentityID(9)}

	upstreamClient, upstreamServer := net.Pipe()
	dialer := &fakeDialer{dialConn: upstreamServer}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer,
		WithOutboundLogf(func(string, ...any) {}),
		WithOutboundTracer(tp.Tracer("meridian-proxy")),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	req := "GET /api HTTP/1.1\r\nHost: svc\r\n\r\n"
	go func() {
		_, _ = client.Write([]byte(req))
		_ = client.Close()
	}()

	buf := make([]byte, 4096)
	_ = upstreamClient.SetDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadAtLeast(upstreamClient, buf, len(req))
	if err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "traceparent: 00-") {
		t.Fatalf("upstream stream missing traceparent header:\n%q", got)
	}
	if !strings.HasPrefix(got, "GET /api HTTP/1.1\r\n") {
		t.Fatalf("request line not preserved:\n%q", got)
	}
	_ = upstreamClient.Close()

	// Span should be recorded once the handler finishes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(rec.Ended()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	attrs := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsInterface()
	}
	if attrs["verdict"] != "allow" || attrs["dst_identity"] != int64(9) || attrs["dst_port"] != int64(8080) {
		t.Fatalf("span attrs = %v, want verdict=allow dst_identity=9 dst_port=8080", attrs)
	}
}
