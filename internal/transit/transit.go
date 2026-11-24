// Package transit checks whether TCP through a peer works when the replies
// come back another way. Some peers run a stateful firewall that drops
// packets of connections whose replies it never saw: the handshake passes,
// then our ACK and data die. Pings and BGP over the link look fine, so only
// a TCP exchange forced through the peer shows it.
//
// A probe connects to a few targets twice: once forced through the peer
// (the SYN included, so the peer's firewall sees the connection start), and
// once over our normal routes as the control. Replies always return however
// the far end routes to us, which is the asymmetric case.
package transit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// Kind is the exchange a target speaks.
type Kind string

const (
	// DNS sends a DNS query over TCP and waits for the answer.
	DNS Kind = "dns"
	// HTTP sends a HEAD request and waits for the response.
	HTTP Kind = "http"
)

// Target is a TCP service to probe.
type Target struct {
	Kind Kind
	Addr netip.AddrPort
}

func (t Target) String() string { return string(t.Kind) + ":" + t.Addr.String() }

// DefaultTargets are anycast services every DN42 network routes: the
// recursive resolver and the wiki.
const DefaultTargets = "dns:[fd42:d42:d42:53::1]:53,http:[fd42:d42:d42:80::1]:80"

// ParseTargets parses "kind:[addr]:port,...".
func ParseTargets(s string) ([]Target, error) {
	var out []Target
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		kind, addr, ok := strings.Cut(f, ":")
		if !ok {
			return nil, fmt.Errorf("transit target %q: want kind:[addr]:port", f)
		}
		k := Kind(kind)
		if k != DNS && k != HTTP {
			return nil, fmt.Errorf("transit target %q: kind must be dns or http", f)
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("transit target %q: %w", f, err)
		}
		if !ap.Addr().Is6() || ap.Addr().Is4In6() || ap.Addr().Zone() != "" {
			return nil, fmt.Errorf("transit target %q: must be a plain IPv6 address", f)
		}
		out = append(out, Target{Kind: k, Addr: ap})
	}
	if len(out) == 0 {
		return nil, errors.New("no transit targets")
	}
	return out, nil
}

// request is what we send; any reply byte counts as an answer.
func (t Target) request() []byte {
	switch t.Kind {
	case DNS:
		// Length-prefixed query for ". NS" with recursion desired.
		return []byte{0, 17, 0xd4, 0x2d, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	default:
		return []byte("HEAD / HTTP/1.0\r\nHost: " + t.Addr.Addr().String() + "\r\nUser-Agent: dn42-operator transit probe\r\n\r\n")
	}
}

// Outcome of one connection attempt.
type Outcome int

const (
	// OK means an answer arrived in time.
	OK Outcome = iota
	// Stalled means the connection opened but no answer arrived (or it was
	// reset), the signature of a peer dropping our packets after the
	// handshake.
	Stalled
	// NoConnect means the handshake didn't complete.
	NoConnect
	// NoRoute means the peer has no route to the target, so it wasn't tried.
	NoRoute
)

func (o Outcome) String() string {
	switch o {
	case OK:
		return "ok"
	case Stalled:
		return "no reply"
	case NoConnect:
		return "no connect"
	default:
		return "no route via the peer"
	}
}

// Attempt is one connection's outcome and how long it took.
type Attempt struct {
	Outcome Outcome
	Took    time.Duration
}

// Dialer opens a TCP connection to the target, forced through the peer when
// steer is true, over the normal routes otherwise.
type Dialer interface {
	Dial(ctx context.Context, dst netip.AddrPort, steer bool) (net.Conn, error)
}

// Net is the probe's view of the network: a Dialer plus the routes that
// force connections through one peer.
type Net interface {
	Dialer
	// Setup prepares the steering (idempotent); Close removes it.
	Setup() error
	Close() error
	// Steer routes dsts through gw on iface until undo runs.
	Steer(iface string, gw netip.Addr, dsts []netip.Addr) (undo func(), err error)
}

// Timeouts of one attempt.
type Timeouts struct {
	Connect time.Duration // handshake (default 3s)
	Reply   time.Duration // first answer byte after sending (default 1.5s)
}

func (t Timeouts) withDefaults() Timeouts {
	if t.Connect == 0 {
		t.Connect = 3 * time.Second
	}
	if t.Reply == 0 {
		t.Reply = 1500 * time.Millisecond
	}
	return t
}

// Try makes one attempt.
func Try(ctx context.Context, d Dialer, t Target, steer bool, to Timeouts) Attempt {
	to = to.withDefaults()
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, to.Connect)
	conn, err := d.Dial(cctx, t.Addr, steer)
	cancel()
	if err != nil {
		return Attempt{Outcome: NoConnect, Took: time.Since(start)}
	}
	defer func() { _ = conn.Close() }()
	sent := time.Now()
	_ = conn.SetDeadline(sent.Add(to.Reply))
	if _, err := conn.Write(t.request()); err != nil {
		return Attempt{Outcome: Stalled, Took: time.Since(start)}
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		return Attempt{Outcome: Stalled, Took: time.Since(start)}
	}
	return Attempt{Outcome: OK, Took: time.Since(start)}
}

// Check is one target probed both ways.
type Check struct {
	Target  Target
	Via     Attempt // forced through the peer
	Control Attempt // over the normal routes
}

// Judge turns the checks into a result and a message. A target counts only
// when the control answered: then the peer is broken for it unless the
// forced attempt answered too. One broken target is enough (the targets
// whose replies happen to come back through the same peer can't show the
// problem); flapping is handled by requiring two results in a row.
func Judge(checks []Check) (result, message string) {
	ok, broken := 0, 0
	parts := make([]string, 0, len(checks))
	for _, c := range checks {
		switch {
		case c.Via.Outcome == NoRoute:
			parts = append(parts, c.Target.String()+": "+NoRoute.String())
		case c.Control.Outcome != OK:
			parts = append(parts, fmt.Sprintf("%s: control failed (%s), not counted", c.Target, c.Control.Outcome))
		case c.Via.Outcome == OK:
			ok++
			parts = append(parts, fmt.Sprintf("%s: ok in %s (control %s)", c.Target, ms(c.Via.Took), ms(c.Control.Took)))
		default:
			broken++
			parts = append(parts, fmt.Sprintf("%s: %s via the peer after %s, control ok in %s", c.Target, c.Via.Outcome, ms(c.Via.Took), ms(c.Control.Took)))
		}
	}
	msg := strings.Join(parts, "; ")
	switch {
	case broken > 0:
		return dn42v1.TransitBroken, msg
	case ok > 0:
		return dn42v1.TransitHealthy, msg
	default:
		return dn42v1.TransitInconclusive, msg
	}
}

func ms(d time.Duration) string { return d.Round(time.Millisecond).String() }
