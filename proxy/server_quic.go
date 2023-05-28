package proxy

import (
	"strings"
	"time"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
// Current draft version: https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02
const NextProtoDQ = "doq-i02"

// maxQuicIdleTimeout - maximum QUIC idle timeout.
// Default value in quic-go is 30, but our internal tests show that
// a higher value works better for clients written with ngtcp2
const maxQuicIdleTimeout = 5 * time.Minute

// compatProtoDQ - ALPNs for backwards compatibility
var compatProtoDQ = []string{"doq-i00", "dq", "doq"}

// handleQUICSession handles a new QUIC session.  It waits for new streams and
// passes them to handleQUICStream.
//
// See also the comment on Proxy.requestGoroutinesSema.
// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the responses
// Writes a response to the QUIC stream
func (p *Proxy) respondQUIC(d *DNSContext) error {
	return nil
}

func isQuicConnClosedErr(err error) bool {
	if err == nil {
		return false
	}

	str := err.Error()

	if strings.Contains(str, "server closed") {
		return true
	}

	if strings.Contains(str, "No recent network activity") {
		return true
	}

	if strings.HasSuffix(str, "Application error 0x0") {
		return true
	}

	if err.Error() == "EOF" {
		return true
	}

	return false
}
