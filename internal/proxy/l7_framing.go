package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"

	"github.com/joshuawu/meridian/pkg/wire"
)

// peekAndMatchL7 peeks at the start of conn, attempts to parse an HTTP request,
// and evaluates it against rules. It returns the verdict, the parsed request
// (nil for non-HTTP streams), and a reader that replays the peeked bytes so
// the caller can still proxy the full stream regardless of verdict.
//
// If the stream does not look like HTTP/1.1 (no valid request line), it returns
// PolicyActionAllow with the original stream (pass-through for non-HTTP flows).
// HTTP/2 detection (PRI * HTTP/2.0) returns allow without L7 matching — full
// HTTP/2 framing is deferred (shortcoming #6 update: needs HPACK support).
func peekAndMatchL7(conn io.Reader, rules []wire.CompiledL7Rule) (wire.PolicyAction, *http.Request, io.Reader) {
	// Buffer up to 8 KB — enough to see the request line + common headers.
	const peekSize = 8192
	br := bufio.NewReaderSize(conn, peekSize)

	// Peek the first bytes without consuming.
	peeked, err := br.Peek(peekSize)
	if err != nil && len(peeked) == 0 {
		return wire.PolicyActionAllow, nil, br // empty stream
	}

	// HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if bytes.HasPrefix(peeked, []byte("PRI * HTTP/2.0")) {
		// HTTP/2: pass through — full framing support deferred.
		return wire.PolicyActionAllow, nil, br
	}

	// Try to parse as HTTP/1.1 request.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(peeked)))
	if err != nil {
		// Not HTTP — pass through.
		return wire.PolicyActionAllow, nil, br
	}

	verdict := MatchL7(rules, req)
	// br still has all bytes buffered (we peeked, didn't read).
	return verdict.Action, req, br
}
