// Package latency measures the RTT to a peer's endpoint and maps it to the
// DN42 latency community (https://dn42.eu/howto/BGP-communities).
package latency

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Upper bounds (inclusive) of latency communities 1..8; above the last is 9.
var bounds = []time.Duration{
	2700 * time.Microsecond,
	7300 * time.Microsecond,
	20 * time.Millisecond,
	55 * time.Millisecond,
	148 * time.Millisecond,
	403 * time.Millisecond,
	1097 * time.Millisecond,
	2981 * time.Millisecond,
}

// Community maps an RTT to the DN42 latency community 1..9.
func Community(rtt time.Duration) int32 {
	for i, b := range bounds {
		if rtt <= b {
			return int32(i + 1)
		}
	}
	return 9
}

// Median of the samples; at least half of count must have answered.
func Median(samples []time.Duration, count int) (time.Duration, error) {
	if len(samples) == 0 || len(samples)*2 < count {
		return 0, fmt.Errorf("only %d of %d pings answered", len(samples), count)
	}
	s := append([]time.Duration(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return s[n/2], nil
	}
	return (s[n/2-1] + s[n/2]) / 2, nil
}

// Pinger sends count echo requests to addr and returns the RTTs of the
// replies.
type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr, count int, interval time.Duration) ([]time.Duration, error)
}

// Measure pings and returns the median RTT and its community.
func Measure(ctx context.Context, p Pinger, addr netip.Addr, count int, interval time.Duration) (time.Duration, int32, error) {
	rtts, err := p.Ping(ctx, addr, count, interval)
	if err != nil && len(rtts) == 0 {
		return 0, 0, err
	}
	m, err := Median(rtts, count)
	if err != nil {
		return 0, 0, err
	}
	return m, Community(m), nil
}

// ICMP pings with raw ICMP sockets (needs CAP_NET_RAW; the router pod is
// privileged). The socket is not bound to the VRF, so the probe takes the
// underlay path the tunnel uses.
type ICMP struct {
	// Timeout for each reply after the last request.
	Timeout time.Duration
}

// Ping implements Pinger.
func (p ICMP) Ping(ctx context.Context, addr netip.Addr, count int, interval time.Duration) ([]time.Duration, error) {
	addr = addr.Unmap()
	network, listen, proto := "ip4:icmp", "0.0.0.0", 1
	var reqType, repType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if addr.Is6() {
		network, listen, proto = "ip6:ipv6-icmp", "::", 58
		reqType, repType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return nil, fmt.Errorf("icmp socket: %w", err)
	}
	defer conn.Close()

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	id := rand.IntN(0xffff)
	dst := &net.IPAddr{IP: addr.AsSlice()}
	var mu sync.Mutex
	sent := make(map[int]time.Time, count)
	var rtts []time.Duration
	done := make(chan struct{})

	go func() { // reader
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			now := time.Now()
			if fa, ok := from.(*net.IPAddr); !ok || !fa.IP.Equal(dst.IP) {
				continue
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || m.Type != repType {
				continue
			}
			e, ok := m.Body.(*icmp.Echo)
			if !ok || e.ID != id {
				continue
			}
			mu.Lock()
			if t, ok := sent[e.Seq]; ok {
				rtts = append(rtts, now.Sub(t))
				delete(sent, e.Seq) // count duplicates once
			}
			mu.Unlock()
		}
	}()

	var sendErr error
	for seq := 0; seq < count; seq++ {
		if seq > 0 {
			select {
			case <-ctx.Done():
				sendErr = ctx.Err()
			case <-time.After(interval):
			}
			if sendErr != nil {
				break
			}
		}
		msg := icmp.Message{Type: reqType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("dn42-operator")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		sent[seq] = time.Now()
		mu.Unlock()
		if _, err := conn.WriteTo(b, dst); err != nil {
			sendErr = err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(rtts) == 0 {
		if sendErr != nil {
			return nil, sendErr
		}
		return nil, errors.New("no replies")
	}
	return rtts, nil
}
