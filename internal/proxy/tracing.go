package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/joshuawu/meridian/pkg/wire"
)

// NewTracerProvider returns the proxy's TracerProvider (P5.4).
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is set, spans are exported via OTLP/HTTP
// to that endpoint (the exporter's own default is localhost:4318). When the
// variable is unset the provider is a no-op, so tracing adds no behavior and
// no network dependency — existing deployments and tests are unchanged.
//
// The returned shutdown function flushes pending spans; call it on agent exit.
func NewTracerProvider(ctx context.Context) (trace.TracerProvider, func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx) // honors OTEL_EXPORTER_OTLP_* env vars
	if err != nil {
		return nil, nil, fmt.Errorf("tracing: create OTLP exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("meridian-proxy"),
		)),
	)
	return tp, tp.Shutdown, nil
}

// connSpan wraps one per-connection span. All methods are nil-safe so
// handlers can call them unconditionally when tracing is disabled.
type connSpan struct {
	span  trace.Span
	start time.Time
}

// startConnSpan begins a span for one proxied connection. A nil tracer
// (tracing disabled) returns a nil connSpan and the context unchanged.
func startConnSpan(ctx context.Context, tracer trace.Tracer, name string) (context.Context, *connSpan) {
	if tracer == nil {
		return ctx, nil
	}
	ctx, span := tracer.Start(ctx, name)
	return ctx, &connSpan{span: span, start: time.Now()}
}

// end records the connection outcome attributes and finishes the span.
func (s *connSpan) end(srcID, dstID wire.IdentityID, dstPort uint16, verdict string) {
	if s == nil {
		return
	}
	s.span.SetAttributes(
		attribute.Int64("src_identity", int64(srcID)),
		attribute.Int64("dst_identity", int64(dstID)),
		attribute.Int("dst_port", int(dstPort)),
		attribute.String("verdict", verdict),
		attribute.Int64("latency_ns", time.Since(s.start).Nanoseconds()),
	)
	s.span.End()
}

// traceparent returns the W3C traceparent header value for this span
// (version 00), or "" when tracing is disabled or the span is not sampled
// into a valid context.
func (s *connSpan) traceparent() string {
	if s == nil {
		return ""
	}
	sc := s.span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return fmt.Sprintf("00-%s-%s-%s", sc.TraceID(), sc.SpanID(), sc.TraceFlags())
}

// injectTraceparent returns a reader replaying r with a traceparent header
// inserted directly after the HTTP/1.1 request line (W3C trace context
// propagation on outbound L7 flows). Streams that do not start with an
// HTTP/1.x request line pass through unmodified, as does an empty header.
func injectTraceparent(r io.Reader, traceparent string) io.Reader {
	if traceparent == "" {
		return r
	}
	const peekSize = 8192
	br := bufio.NewReaderSize(r, peekSize)
	peeked, err := br.Peek(peekSize)
	if len(peeked) == 0 && err != nil {
		return br
	}
	idx := bytes.Index(peeked, []byte("\r\n"))
	if idx < 0 || !isHTTP1RequestLine(peeked[:idx]) {
		return br
	}
	// Consume the request line and replay it with the header appended.
	line := make([]byte, idx+2)
	if _, err := io.ReadFull(br, line); err != nil {
		return io.MultiReader(bytes.NewReader(line), br)
	}
	head := append(line, []byte("traceparent: "+traceparent+"\r\n")...)
	return io.MultiReader(bytes.NewReader(head), br)
}

// isHTTP1RequestLine reports whether line looks like "METHOD target HTTP/1.x".
func isHTTP1RequestLine(line []byte) bool {
	parts := bytes.Split(line, []byte(" "))
	return len(parts) == 3 && bytes.HasPrefix(parts[2], []byte("HTTP/1."))
}
