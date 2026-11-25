package controller

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/transit"
)

// fakeTransitNet answers every unsteered connection and, for steered ones,
// answers only while the steered link isn't in broken.
type fakeTransitNet struct {
	t          *testing.T
	answering  string
	silent     string
	broken     map[string]bool // interface -> drops after the handshake
	steeredVia string
	setups     int
	steers     []string
}

func (f *fakeTransitNet) Setup() error { f.setups++; return nil }
func (f *fakeTransitNet) Close() error { return nil }

func (f *fakeTransitNet) Steer(iface string, gw netip.Addr, dsts []netip.Addr) (func(), error) {
	f.steeredVia = iface
	f.steers = append(f.steers, iface+" via "+gw.String())
	return func() { f.steeredVia = "" }, nil
}

func (f *fakeTransitNet) Dial(ctx context.Context, _ netip.AddrPort, steer bool) (net.Conn, error) {
	a := f.answering
	if steer {
		if f.steeredVia == "" {
			f.t.Error("steered dial outside Steer")
		}
		if f.broken[f.steeredVia] {
			a = f.silent
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", a)
}

type fakeRoutes map[string]bool // protocol -> has routes to the targets

func (f fakeRoutes) HasRoute(_ context.Context, protocol string, _ netip.Addr) (bool, error) {
	return f[protocol], nil
}

func loopServer(t *testing.T, answer bool) string {
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
				if _, err := c.Read(buf); err == nil && answer {
					_, _ = c.Write([]byte("ok"))
				} else {
					time.Sleep(time.Second)
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

func established(p *dn42v1.DN42Peer) *dn42v1.DN42Peer {
	now := metav1.NewTime(created)
	p.Status.Conditions = []metav1.Condition{
		{Type: dn42v1.ConditionValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: now},
		{Type: dn42v1.ConditionSessionEstablished, Status: metav1.ConditionTrue, Reason: "Established", LastTransitionTime: now},
	}
	return p
}

func TestTransitProber(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	bad := established(mkPeer("baragoon", 4242421732, 0, "fe80::1732", 0))
	good := established(mkPeer("routedbits", 4242420207, 0, "fe80::207", 0))
	noroute := established(mkPeer("stub", 4242420003, 0, "fe80::3", 0))
	down := mkPeer("down", 4242420004, 0, "fe80::4", 0) // no established session
	u := newUnit(t, bad, good, noroute, down, keySecret(t, "autopeer"), endpointService())
	u.r.Now = func() time.Time { return now }
	u.r.Renderer.TransitArg = true
	for _, n := range []string{"baragoon", "routedbits", "stub"} {
		u.fb.protos["peer_"+n] = bird.ProtocolStatus{Name: "peer_" + n, Proto: "BGP", State: "up", BGPState: "Established"}
	}
	fn := &fakeTransitNet{t: t, answering: loopServer(t, true), silent: loopServer(t, false),
		broken: map[string]bool{"wg-baragoon": true}}
	tp := &TransitProber{R: u.r, Net: fn,
		Routes:   fakeRoutes{"peer_baragoon": true, "peer_routedbits": true},
		Targets:  []transit.Target{{Kind: transit.DNS, Addr: netip.MustParseAddrPort("[fd42:d42:d42:53::1]:53")}},
		Timeouts: transit.Timeouts{Connect: time.Second, Reply: 100 * time.Millisecond}}
	run := func() bool {
		t.Helper()
		changed, err := tp.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	file := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(u.path, name+".conf"))
		return string(b)
	}
	transitOf := func(name string) *dn42v1.TransitStatus { return u.peer(name).Status.Transit }

	// Unprobed peers render transit_ok true.
	u.mustPass()
	if !strings.Contains(file("baragoon"), "dn42_import_transit(5, 24, 34, true);") {
		t.Fatalf("before probing:\n%s", file("baragoon"))
	}

	// First probe: results recorded, no verdict yet.
	if run() {
		t.Error("verdict after one probe")
	}
	if fn.setups != 1 || strings.Join(fn.steers, ",") != "wg-baragoon via fe80::1732,wg-routedbits via fe80::207" {
		t.Errorf("setups %d, steered %v", fn.setups, fn.steers)
	}
	if st := transitOf("baragoon"); st.LastResult != dn42v1.TransitBroken || st.Healthy != nil ||
		!strings.Contains(st.Message, "no reply via the peer") {
		t.Fatalf("baragoon after one probe: %+v", st)
	}
	if st := transitOf("stub"); st.LastResult != dn42v1.TransitInconclusive || !strings.Contains(st.Message, "no route") {
		t.Errorf("stub: %+v", st)
	}
	if transitOf("down") != nil {
		t.Error("peer without a session probed")
	}

	// Not again right away; confirmed after Confirm. A round with nothing
	// due doesn't touch the steering; one that probes checks it again.
	now = now.Add(time.Minute)
	if run() || len(fn.steers) != 2 || fn.setups != 1 {
		t.Errorf("re-probed before Confirm (setups %d)", fn.setups)
	}
	now = now.Add(5 * time.Minute)
	if !run() {
		t.Error("no verdict after two agreeing probes")
	}
	if fn.setups != 2 {
		t.Errorf("steering not re-checked for the second round: setups %d", fn.setups)
	}
	if h := transitOf("baragoon").Healthy; h == nil || *h {
		t.Fatalf("baragoon verdict %v", h)
	}
	if h := transitOf("routedbits").Healthy; h == nil || !*h {
		t.Fatalf("routedbits verdict %v", h)
	}
	if transitOf("stub").Healthy != nil {
		t.Error("inconclusive probes gave a verdict")
	}

	// The next pass renders it; status shows the condition.
	u.mustPass()
	if !strings.Contains(file("baragoon"), "dn42_import_transit(5, 24, 34, false);") ||
		!strings.Contains(file("routedbits"), "dn42_import_transit(5, 24, 34, true);") {
		t.Fatalf("after verdict:\n%s\n%s", file("baragoon"), file("routedbits"))
	}
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := u.cond("baragoon", dn42v1.ConditionTransitHealthy); c.Status != metav1.ConditionFalse || c.Reason != dn42v1.TransitBroken {
		t.Errorf("baragoon condition %+v", c)
	}
	if c := u.cond("routedbits", dn42v1.ConditionTransitHealthy); c.Status != metav1.ConditionTrue {
		t.Errorf("routedbits condition %+v", c)
	}
	if c := u.cond("stub", dn42v1.ConditionTransitHealthy); c.Status != metav1.ConditionUnknown {
		t.Errorf("stub condition %+v", c)
	}

	// baragoon fixes its firewall: the hourly re-probe disagrees, the
	// condition says so, and the verdict flips after the confirmation.
	fn.broken = nil
	now = now.Add(time.Hour)
	if run() {
		t.Error("flipped after one probe")
	}
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := u.cond("baragoon", dn42v1.ConditionTransitHealthy); c.Status != metav1.ConditionFalse || c.Reason != "Confirming" {
		t.Errorf("confirming condition %+v", c)
	}
	now = now.Add(5 * time.Minute)
	if !run() {
		t.Error("no flip after two agreeing probes")
	}
	u.mustPass()
	if !strings.Contains(file("baragoon"), "dn42_import_transit(5, 24, 34, true);") {
		t.Errorf("after recovery:\n%s", file("baragoon"))
	}

	// A healthy peer waits a day after its last probe.
	probedBaragoon := func() int {
		n := 0
		for _, s := range fn.steers {
			if strings.HasPrefix(s, "wg-baragoon") {
				n++
			}
		}
		return n
	}
	before := probedBaragoon()
	now = now.Add(23 * time.Hour)
	run()
	if probedBaragoon() != before {
		t.Error("healthy peer re-probed within a day")
	}
	now = now.Add(2 * time.Hour)
	run()
	if probedBaragoon() != before+1 {
		t.Error("healthy peer not re-probed after a day")
	}
}

func TestNextTransit(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	steps := []struct {
		result string
		want   *bool
	}{
		{dn42v1.TransitBroken, nil},
		{dn42v1.TransitInconclusive, nil},
		{dn42v1.TransitBroken, nil}, // an inconclusive probe in between resets the count
		{dn42v1.TransitBroken, ptrBool(false)},
		{dn42v1.TransitInconclusive, ptrBool(false)},
		{dn42v1.TransitHealthy, ptrBool(false)},
		{dn42v1.TransitHealthy, ptrBool(true)},
	}
	var st *dn42v1.TransitStatus
	for i, s := range steps {
		st = NextTransit(st, s.result, "m", now)
		if !sameVerdict(st.Healthy, s.want) || st.LastResult != s.result || !st.ProbedAt.Time.Equal(now) {
			t.Fatalf("step %d (%s): %+v", i, s.result, st)
		}
	}
}

func ptrBool(b bool) *bool { return &b }
