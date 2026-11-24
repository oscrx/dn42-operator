package transit

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

func TestParseTargets(t *testing.T) {
	ts, err := ParseTargets(DefaultTargets)
	if err != nil || len(ts) != 2 || ts[0].Kind != DNS || ts[1].Kind != HTTP ||
		ts[0].Addr != netip.MustParseAddrPort("[fd42:d42:d42:53::1]:53") {
		t.Fatalf("defaults: %v %v", ts, err)
	}
	if ts[1].String() != "http:[fd42:d42:d42:80::1]:80" {
		t.Errorf("String: %s", ts[1])
	}
	for _, bad := range []string{"", " , ", "ftp:[fd42::1]:21", "dns:192.0.2.1:53", "dns:[::ffff:192.0.2.1]:53",
		"dns:[fe80::1%wg0]:53", "dns:fd42::1", "dns"} {
		if _, err := ParseTargets(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDNSRequestIsLengthPrefixed(t *testing.T) {
	b := Target{Kind: DNS}.request()
	if int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		t.Errorf("length prefix %d for %d bytes", binary.BigEndian.Uint16(b), len(b)-2)
	}
	h := Target{Kind: HTTP, Addr: netip.MustParseAddrPort("[fd42::1]:80")}.request()
	if !strings.HasPrefix(string(h), "HEAD / HTTP/1.0\r\nHost: fd42::1\r\n") || !strings.HasSuffix(string(h), "\r\n\r\n") {
		t.Errorf("http request %q", h)
	}
}

// server listens on loopback; answer false accepts and stays silent, like a
// connection whose packets after the handshake are dropped.
func server(t *testing.T, answer bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if answer {
					_, _ = c.Write([]byte("ok"))
				} else {
					time.Sleep(time.Second)
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

// loopDialer sends steered connections to one address and the rest to
// another, whatever the target.
type loopDialer struct{ via, normal string }

func (d loopDialer) Dial(ctx context.Context, _ netip.AddrPort, steer bool) (net.Conn, error) {
	a := d.normal
	if steer {
		a = d.via
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", a)
}

func TestTry(t *testing.T) {
	answering, silent := server(t, true), server(t, false)
	closed := func() string { // a port nobody listens on
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		a := l.Addr().String()
		_ = l.Close()
		return a
	}()
	to := Timeouts{Connect: time.Second, Reply: 200 * time.Millisecond}
	tgt := Target{Kind: HTTP, Addr: netip.MustParseAddrPort("[fd42::1]:80")}
	d := loopDialer{via: silent, normal: answering}
	if a := Try(context.Background(), d, tgt, false, to); a.Outcome != OK {
		t.Errorf("answering: %v", a.Outcome)
	}
	a := Try(context.Background(), d, tgt, true, to)
	if a.Outcome != Stalled || a.Took < 200*time.Millisecond {
		t.Errorf("silent: %v after %s", a.Outcome, a.Took)
	}
	if a := Try(context.Background(), loopDialer{via: closed}, tgt, true, to); a.Outcome != NoConnect {
		t.Errorf("closed: %v", a.Outcome)
	}
}

func TestJudge(t *testing.T) {
	dns := Target{Kind: DNS, Addr: netip.MustParseAddrPort("[fd42:d42:d42:53::1]:53")}
	web := Target{Kind: HTTP, Addr: netip.MustParseAddrPort("[fd42:d42:d42:80::1]:80")}
	ok := Attempt{Outcome: OK, Took: 40 * time.Millisecond}
	stalled := Attempt{Outcome: Stalled, Took: 1540 * time.Millisecond}
	for _, c := range []struct {
		name   string
		checks []Check
		want   string
		msg    string
	}{
		{"all ok", []Check{{dns, ok, ok}, {web, ok, ok}}, dn42v1.TransitHealthy, "ok in 40ms"},
		{"one stalls", []Check{{dns, ok, ok}, {web, stalled, ok}}, dn42v1.TransitBroken, "no reply via the peer after 1.54s, control ok in 40ms"},
		{"no connect counts as broken", []Check{{dns, Attempt{Outcome: NoConnect}, ok}}, dn42v1.TransitBroken, "no connect"},
		{"control failed: not counted", []Check{{dns, stalled, stalled}}, dn42v1.TransitInconclusive, "control failed"},
		{"no routes", []Check{{dns, Attempt{Outcome: NoRoute}, Attempt{}}, {web, Attempt{Outcome: NoRoute}, Attempt{}}}, dn42v1.TransitInconclusive, "no route via the peer"},
		{"route for one", []Check{{dns, Attempt{Outcome: NoRoute}, Attempt{}}, {web, ok, ok}}, dn42v1.TransitHealthy, "dns:[fd42:d42:d42:53::1]:53: no route"},
	} {
		got, msg := Judge(c.checks)
		if got != c.want || !strings.Contains(msg, c.msg) {
			t.Errorf("%s: %s %q", c.name, got, msg)
		}
	}
}
