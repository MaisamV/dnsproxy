package upstream

import (
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const handshakeTimeout = time.Second

// DNS-over-QUIC
type dnsOverQUIC struct {
	boot *bootstrapper

	bytesPool    *sync.Pool // byte packets pool
	sync.RWMutex            // protects session and bytesPool
}

// type check
var _ Upstream = &dnsOverQUIC{}

func (p *dnsOverQUIC) Address() string { return p.boot.URL.String() }

func (p *dnsOverQUIC) Exchange(m *dns.Msg) (*dns.Msg, error) {

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := m.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				return nil, errors.New("EDNS0 TCP keepalive option is set")
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	id := m.Id
	var reply *dns.Msg
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if reply != nil {
			reply.Id = id
		}
	}()

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.

	pool := p.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	reply = new(dns.Msg)

	return reply, nil
}

func (p *dnsOverQUIC) getBytesPool() *sync.Pool {
	p.Lock()
	if p.bytesPool == nil {
		p.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, dns.MaxMsgSize)

				return &b
			},
		}
	}
	p.Unlock()
	return p.bytesPool
}
