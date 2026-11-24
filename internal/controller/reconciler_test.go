package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/netdev"
	"github.com/oscrx/dn42-operator/internal/netdev/fake"
)

// fakeBird accepts every config and reports canned protocols.
type fakeBird struct {
	protos     map[string]bird.ProtocolStatus
	down       bool
	configures int
}

func (f *fakeBird) ConfigureCheck(context.Context) error {
	if f.down {
		return errors.New("connection refused")
	}
	return nil
}
func (f *fakeBird) Configure(context.Context) error {
	if f.down {
		return errors.New("connection refused")
	}
	f.configures++
	return nil
}
func (f *fakeBird) ShowProtocols(context.Context) (map[string]bird.ProtocolStatus, error) {
	if f.down {
		return nil, errors.New("connection refused")
	}
	return f.protos, nil
}

type unit struct {
	*harness
	nd   *fake.Manager
	fb   *fakeBird
	path string
}

func newUnit(t *testing.T, objs ...client.Object) *unit {
	nd := fake.New("vrf-dn42")
	fb := &fakeBird{protos: map[string]bird.ProtocolStatus{}}
	path := t.TempDir()
	u := &unit{nd: nd, fb: fb, path: path}
	u.harness = newHarness(t, nd, &bird.Dir{Path: path, Bird: fb}, fb, objs...)
	return u
}

func (u *unit) files() []string {
	ents, _ := os.ReadDir(u.path)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func (u *unit) managedLinks() []string {
	ls, _ := u.nd.ListManaged()
	var out []string
	for _, l := range ls {
		out = append(out, l.Name)
	}
	return out
}

func TestLeaderBuildsAndCleansUp(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	a.Spec.KeyRef = "iedon"
	b := mkPeer("tech9", 4242421588, 21588, "fe80::1588", 1)
	u := newUnit(t, a, b, keySecret(t, "iedon", "autopeer"), endpointService())
	u.nd.AddForeign("wg-foreign")
	u.nd.AddForeign("dn42-lo")
	// A managed link whose peer object is gone.
	u.nd.Links["wg-gone"] = &netdev.State{Name: "wg-gone", Alias: netdev.Alias, Sysctls: map[string]string{}}

	u.mustPass()

	if got := strings.Join(u.managedLinks(), ","); got != "wg-iedon,wg-tech9" {
		t.Errorf("managed links: %s", got)
	}
	if _, ok := u.nd.Links["wg-foreign"]; !ok {
		t.Error("foreign link deleted")
	}
	if _, ok := u.nd.Links["dn42-lo"]; !ok {
		t.Error("dn42-lo deleted")
	}
	ie := u.nd.Links["wg-iedon"]
	if ie.ListenPort != 22189 || ie.Master != "vrf-dn42" || ie.Addresses[0].String() != "fe80::3818/64" {
		t.Errorf("wg-iedon: %+v", ie)
	}
	if got := strings.Join(u.files(), ","); got != "iedon.conf,tech9.conf" {
		t.Errorf("files: %s", got)
	}
	ports := u.servicePorts()
	if ports["wg-iedon"] != 22189 || ports["wg-tech9"] != 21588 {
		t.Errorf("service ports: %v", ports)
	}

	// Second pass with nothing changed: no link changes.
	u.nd.Calls = nil
	u.mustPass()
	for _, l := range []string{"wg-iedon", "wg-tech9"} {
		st, _ := u.nd.Inspect(l)
		if p := netdev.Diff(st, &netdev.Spec{Name: l, VRF: "vrf-dn42", PrivateKey: st.PrivateKey, ListenPort: st.ListenPort,
			PeerPublicKey: st.Peers[0].PublicKey, Endpoint: st.Peers[0].Endpoint, Address: st.Addresses[0]}, u.r.now()); !p.Empty() {
			t.Errorf("%s not converged: %v", l, p.Description)
		}
	}
	if u.fb.configures != 1 {
		t.Errorf("bird reconfigured %d times, want 1", u.fb.configures)
	}

	// Delete one peer: its link, file and port go.
	u.delete(b)
	u.mustPass()
	if got := strings.Join(u.managedLinks(), ","); got != "wg-iedon" {
		t.Errorf("after delete: %s", got)
	}
	if got := strings.Join(u.files(), ","); got != "iedon.conf" {
		t.Errorf("files after delete: %s", got)
	}
	if _, ok := u.servicePorts()["wg-tech9"]; ok {
		t.Error("service port of deleted peer kept")
	}
}

func TestAPIOutageChangesNothing(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	u := newUnit(t, a, keySecret(t, "autopeer"), endpointService())
	u.mustPass()
	before := u.files()
	u.nd.Calls = nil

	u.listOK = false
	if err := u.pass(); err == nil {
		t.Fatal("pass succeeded while the API was down")
	}
	if len(u.nd.Calls) != 0 {
		t.Errorf("links touched during outage: %v", u.nd.Calls)
	}
	if got := u.managedLinks(); len(got) != 1 {
		t.Errorf("links: %v", got)
	}
	if strings.Join(u.files(), ",") != strings.Join(before, ",") {
		t.Errorf("files changed: %v", u.files())
	}
	if u.r.Ready() == nil {
		t.Error("ready after a failed pass")
	}
}

func TestMassDeletionBlocked(t *testing.T) {
	var objs []client.Object
	objs = append(objs, keySecret(t, "autopeer"), endpointService())
	var peers []*dn42v1.DN42Peer
	for i, n := range []string{"aa", "bb", "cc", "dd"} {
		p := mkPeer(n, int64(4242420001+i), 0, "fe80::1", i)
		peers = append(peers, p)
		objs = append(objs, p)
	}
	u := newUnit(t, objs...)
	u.mustPass()
	if len(u.managedLinks()) != 4 {
		t.Fatalf("links: %v", u.managedLinks())
	}
	// Three of four disappear at once: blocked.
	for _, p := range peers[1:] {
		u.delete(p)
	}
	u.mustPass()
	if len(u.managedLinks()) != 4 || len(u.files()) != 4 {
		t.Fatalf("mass deletion went through: %v %v", u.managedLinks(), u.files())
	}
	// Wrong count doesn't confirm.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "control"},
		Data: map[string]string{ConfirmDeletionsKey: "2"}}
	u.create(cm)
	u.mustPass()
	if len(u.managedLinks()) != 4 {
		t.Fatal("confirmed with the wrong count")
	}
	cm.Data[ConfirmDeletionsKey] = "3"
	if err := u.c.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	u.mustPass()
	if got := strings.Join(u.managedLinks(), ","); got != "wg-aa" {
		t.Errorf("after confirmation: %s", got)
	}
	if got := strings.Join(u.files(), ","); got != "aa.conf" {
		t.Errorf("files after confirmation: %s", got)
	}
}

func TestSingleDeletionAllowed(t *testing.T) {
	a := mkPeer("aa", 4242420001, 0, "fe80::1", 0)
	u := newUnit(t, a, keySecret(t, "autopeer"))
	u.r.EndpointService = ""
	u.mustPass()
	u.delete(a)
	u.mustPass()
	if len(u.managedLinks()) != 0 {
		t.Errorf("last link not deleted: %v", u.managedLinks())
	}
}

func TestFollowerAndUnknown(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	u := newUnit(t, a, keySecret(t, "autopeer"), endpointService())
	u.nd.AddForeign("wg-foreign")
	u.mustPass()

	u.r.State.Set(RoleUnknown)
	u.nd.Calls = nil
	u.mustPass()
	if len(u.nd.Calls) != 0 || len(u.managedLinks()) != 1 {
		t.Errorf("unknown role changed links: %v", u.nd.Calls)
	}

	u.r.State.Set(RoleFollower)
	u.mustPass()
	if len(u.managedLinks()) != 0 || len(u.files()) != 0 {
		t.Errorf("follower kept state: %v %v", u.managedLinks(), u.files())
	}
	if _, ok := u.nd.Links["wg-foreign"]; !ok {
		t.Error("follower deleted a foreign link")
	}
	if err := u.r.Ready(); err != nil {
		t.Errorf("healthy follower not ready: %v", err)
	}
}

func TestInvalidPeerKeepsExisting(t *testing.T) {
	old := mkPeer("old", 4242422189, 0, "fe80::1", 0)
	u := newUnit(t, old, keySecret(t, "autopeer"), endpointService())
	u.mustPass()

	// A newer peer claims the same port: it is invalid, old is untouched.
	newer := mkPeer("newer", 4242420002, 22189, "fe80::2", 5)
	u.create(newer)
	// A non-4242 ASN without a port.
	neo := mkPeer("neo", 4201270001, 0, "fe80::3", 6)
	u.create(neo)
	u.nd.Calls = nil
	u.mustPass()
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(u.nd.Calls, ","); got != "ensure wg-old" {
		t.Errorf("calls: %s", got)
	}
	c := u.cond("newer", dn42v1.ConditionValid)
	if c.Status != metav1.ConditionFalse || c.Reason != "PortConflict" || !strings.Contains(c.Message, "old") {
		t.Errorf("newer: %+v", c)
	}
	c = u.cond("neo", dn42v1.ConditionValid)
	if c.Status != metav1.ConditionFalse || c.Reason != "ListenPortRequired" {
		t.Errorf("neo: %+v", c)
	}
	if u.cond("old", dn42v1.ConditionValid).Status != metav1.ConditionTrue {
		t.Error("old not valid")
	}
	if got := strings.Join(u.files(), ","); got != "old.conf" {
		t.Errorf("files: %s", got)
	}
}

func TestInterfaceConflictAndMissingKey(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	b := mkPeer("tech9", 4242421588, 0, "fe80::1588", 1)
	b.Spec.KeyRef = "tech9" // not in the secret
	u := newUnit(t, a, b, keySecret(t, "autopeer"), endpointService())
	u.nd.AddForeign("wg-iedon") // still owned by Talos
	u.mustPass()
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := u.cond("iedon", dn42v1.ConditionTunnelReady); c.Reason != ReasonInterfaceConflict {
		t.Errorf("iedon: %+v", c)
	}
	if u.nd.Links["wg-iedon"].Managed() {
		t.Error("foreign wg-iedon was taken over")
	}
	if c := u.cond("tech9", dn42v1.ConditionTunnelReady); c.Reason != ReasonKeyMissing {
		t.Errorf("tech9: %+v", c)
	}
	if len(u.files()) != 0 {
		t.Errorf("files for peers without tunnel: %v", u.files())
	}
}

func TestStatus(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	a.Spec.Link = &dn42v1.LinkValues{Latency: 2, Bandwidth: 24, Crypto: 34}
	u := newUnit(t, a, keySecret(t, "autopeer"), endpointService())
	u.fb.protos["peer_iedon"] = bird.ProtocolStatus{Name: "peer_iedon", Proto: "BGP", State: "up",
		BGPState: "Established", RoutesImported: 412, HasRoutes: true}
	u.mustPass()
	u.nd.Links["wg-iedon"].Peers[0].LastHandshake = u.r.now()
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := u.peer("iedon")
	s := p.Status
	if s.BGPState != "Established" || s.RoutesImported == nil || *s.RoutesImported != 412 ||
		s.ListenPort != 22189 || s.Interface != "wg-iedon" || s.LastHandshake == nil || s.Link.Latency != 2 {
		t.Errorf("status: %+v", s)
	}
	for _, typ := range []string{dn42v1.ConditionValid, dn42v1.ConditionTunnelReady, dn42v1.ConditionSessionEstablished} {
		if c := u.cond("iedon", typ); c.Status != metav1.ConditionTrue {
			t.Errorf("%s: %+v", typ, c)
		}
	}
	rv := p.ResourceVersion
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u.peer("iedon").ResourceVersion != rv {
		t.Error("unchanged status was written again")
	}
	if err := u.r.Ready(); err != nil {
		t.Errorf("leader not ready: %v", err)
	}

	// BIRD down: tunnels stay, pass reports it, not ready.
	u.fb.down = true
	u.create(mkPeer("tech9", 4242421588, 0, "fe80::1588", 1))
	if err := u.pass(); err == nil {
		t.Error("pass ok with bird down")
	}
	if len(u.managedLinks()) != 2 {
		t.Errorf("links: %v", u.managedLinks())
	}
	if _, err := os.Stat(filepath.Join(u.path, "tech9.conf")); err == nil {
		t.Error("file written without configure check")
	}
	if u.r.Ready() == nil {
		t.Error("ready with bird down")
	}
}

func pod(name, leader string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
		Labels: map[string]string{"app.kubernetes.io/name": "dn42-router"}}}
	if leader != "" {
		p.Labels[DefaultLeaderLabel] = leader
	}
	return p
}

func TestLeaderLabel(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	u := newUnit(t, a, keySecret(t, "autopeer"), endpointService(),
		pod("router-a", ""), pod("router-b", "true"), pod("router-c", "false"))
	u.r.Labeler = &PodLabeler{Client: u.c, Reader: u.c, Namespace: ns, PodName: "router-a", Label: DefaultLeaderLabel}
	label := func(name string) string {
		var p corev1.Pod
		if err := u.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &p); err != nil {
			t.Fatal(err)
		}
		return p.Labels[DefaultLeaderLabel]
	}

	// Unknown role: not ready, labels untouched.
	u.r.State.Set(RoleUnknown)
	u.mustPass()
	if u.r.Ready() == nil || label("router-b") != "true" {
		t.Error("unknown role ready or labels changed")
	}

	// Leader: own label true, the stale leader label on b is cleared.
	u.r.State.Set(RoleLeader)
	u.mustPass()
	if label("router-a") != "true" || label("router-b") != "false" || label("router-c") != "false" {
		t.Errorf("labels: a=%s b=%s c=%s", label("router-a"), label("router-b"), label("router-c"))
	}
	if err := u.r.Ready(); err != nil {
		t.Errorf("leader not ready: %v", err)
	}

	// Follower: own label false, still ready (healthy).
	u.r.State.Set(RoleFollower)
	u.mustPass()
	if label("router-a") != "false" {
		t.Error("follower kept the leader label")
	}
	if err := u.r.Ready(); err != nil {
		t.Errorf("follower not ready: %v", err)
	}

	// The role changes but the label can't be written: not ready, so the
	// pod never sits in the Service with a label that doesn't match.
	u.r.Labeler.PodName = "gone"
	u.r.State.Set(RoleLeader)
	if err := u.pass(); err == nil {
		t.Error("pass ok without the label")
	}
	if u.r.Ready() == nil {
		t.Error("ready without a confirmed label")
	}
}

type fixedPinger struct {
	rtt   time.Duration
	fail  bool
	calls int
	addrs []string // pinged, in order
}

func (f *fixedPinger) Ping(_ context.Context, addr netip.Addr, count int, _ time.Duration) ([]time.Duration, error) {
	f.calls++
	f.addrs = append(f.addrs, addr.String())
	if f.fail {
		return nil, errors.New("no replies")
	}
	out := make([]time.Duration, count)
	for i := range out {
		out[i] = f.rtt
	}
	return out, nil
}

func TestLatencyProber(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	measured := mkPeer("measured", 4242420001, 0, "fe80::1", 0)
	fixed := mkPeer("fixed", 4242420002, 0, "fe80::2", 0)
	fixed.Spec.Link = &dn42v1.LinkValues{Latency: 2, Bandwidth: 25, Crypto: 34}
	noEndpoint := mkPeer("noep", 4242420003, 0, "fe80::3", 0)
	noEndpoint.Spec.Endpoint = ""
	u := newUnit(t, measured, fixed, noEndpoint, keySecret(t, "autopeer"), endpointService())
	u.r.Now = func() time.Time { return now }
	pinger := &fixedPinger{rtt: 30 * time.Millisecond}
	lp := &LatencyProber{R: u.r, Pinger: pinger, Interval: time.Nanosecond}

	// Before measuring, the default latency (5) is rendered.
	u.mustPass()
	if b, _ := os.ReadFile(filepath.Join(u.path, "measured.conf")); !strings.Contains(string(b), "dn42_import(5, 24, 34)") {
		t.Errorf("default not rendered:\n%s", b)
	}

	n, err := lp.Run(context.Background())
	if err != nil || n != 1 || pinger.calls != 1 {
		t.Fatalf("run: n=%d calls=%d err=%v", n, pinger.calls, err)
	}
	s := u.peer("measured").Status
	if s.MeasuredLatency == nil || *s.MeasuredLatency != 4 || s.MeasuredRTT.Duration != 30*time.Millisecond ||
		s.LatencyMeasuredAt == nil || !s.LatencyMeasuredAt.Time.Equal(now) {
		t.Fatalf("status: %+v", s)
	}
	if u.peer("fixed").Status.MeasuredLatency != nil {
		t.Error("peer with spec.link measured")
	}

	// The next pass renders the measured value, and status shows it.
	u.mustPass()
	if b, _ := os.ReadFile(filepath.Join(u.path, "measured.conf")); !strings.Contains(string(b), "dn42_import(4, 24, 34)") {
		t.Errorf("measured latency not rendered:\n%s", b)
	}
	if err := u.r.UpdateStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := u.peer("measured").Status; st.Link.Latency != 4 || *st.MeasuredLatency != 4 {
		t.Errorf("status after pass: %+v", st)
	}
	if b, _ := os.ReadFile(filepath.Join(u.path, "fixed.conf")); !strings.Contains(string(b), "dn42_import(2, 25, 34)") {
		t.Error("spec.link not used")
	}

	// Not again within a day; again after.
	now = now.Add(23 * time.Hour)
	if n, _ := lp.Run(context.Background()); n != 0 {
		t.Error("re-measured within a day")
	}
	now = now.Add(2 * time.Hour)
	pinger.rtt = 5 * time.Millisecond
	if n, _ := lp.Run(context.Background()); n != 1 || *u.peer("measured").Status.MeasuredLatency != 2 {
		t.Error("not re-measured after a day")
	}

	// A failed measurement keeps the old value and retries after an hour.
	now = now.Add(25 * time.Hour)
	pinger.fail = true
	if n, _ := lp.Run(context.Background()); n != 0 || *u.peer("measured").Status.MeasuredLatency != 2 {
		t.Error("failed measurement changed status")
	}
	calls := pinger.calls
	now = now.Add(30 * time.Minute)
	_, _ = lp.Run(context.Background()) // the attempt is what counts here
	if pinger.calls != calls {
		t.Error("retried within the hour")
	}
	now = now.Add(31 * time.Minute)
	pinger.fail = false
	if n, _ := lp.Run(context.Background()); n != 1 {
		t.Error("no retry after an hour")
	}
	if u.peer("noep").Status.MeasuredLatency != nil {
		t.Error("peer without endpoint measured before it connected")
	}

	// Where WireGuard sees the peer is what gets pinged: a peer without
	// spec.endpoint once it connected, and a peer that moved.
	u.nd.Roam("wg-noep", &net.UDPAddr{IP: net.ParseIP("2001:db8::33"), Port: 51820})
	u.mustPass() // a pass keeps the learned endpoint of a peer without spec.endpoint
	// (A configured endpoint is only restored when the handshake is stale;
	// the fake has none, so roam after the pass, as with a live tunnel.)
	u.nd.Roam("wg-measured", &net.UDPAddr{IP: net.ParseIP("2001:db8::44"), Port: 51820})
	now = now.Add(25 * time.Hour)
	pinger.addrs = nil
	if n, _ := lp.Run(context.Background()); n != 2 || u.peer("noep").Status.MeasuredLatency == nil {
		t.Fatalf("after connecting: n=%d status %+v", n, u.peer("noep").Status)
	}
	if got := strings.Join(pinger.addrs, ","); got != "2001:db8::44,2001:db8::33" {
		t.Errorf("pinged %s, want the live endpoints 2001:db8::44,2001:db8::33", got)
	}
}

func TestPerPeerMTUAndLinkLocal(t *testing.T) {
	zz := mkPeer("zz", 4242421144, 21144, "fe80::1", 0)
	zz.Spec.LocalLinkLocal = "fe80::2"
	zz.Spec.KeyRef = "zz"
	yuk := mkPeer("yukifia", 4242420091, 20091, "fe80::91", 1)
	mtu := int32(1380)
	yuk.Spec.MTU = &mtu
	yuk.Spec.KeyRef = "yukifia"
	u := newUnit(t, zz, yuk, keySecret(t, "zz", "yukifia"), endpointService())
	u.mustPass()
	z, y := u.nd.Links["wg-zz"], u.nd.Links["wg-yukifia"]
	if z == nil || y == nil {
		t.Fatalf("links: %v", u.managedLinks())
	}
	if z.Addresses[0].String() != "fe80::2/64" || z.MTU != 1420 {
		t.Errorf("wg-zz: addr %v mtu %d", z.Addresses, z.MTU)
	}
	if y.Addresses[0].String() != "fe80::3818/64" || y.MTU != 1380 {
		t.Errorf("wg-yukifia: addr %v mtu %d", y.Addresses, y.MTU)
	}
	b, _ := os.ReadFile(filepath.Join(u.path, "zz.conf"))
	if !strings.Contains(string(b), "neighbor fe80::1 as 4242421144;") {
		t.Errorf("zz.conf:\n%s", b)
	}
}

func TestStandDownSwitch(t *testing.T) {
	a := mkPeer("iedon", 4242422189, 0, "fe80::2189:177", 0)
	u := newUnit(t, a, keySecret(t, "autopeer"), endpointService())
	u.mustPass()
	if len(u.managedLinks()) != 1 {
		t.Fatal("no link")
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "control"},
		Data: map[string]string{StandDownKey: "true"}}
	u.create(cm)
	u.mustPass()
	if len(u.managedLinks()) != 0 || len(u.files()) != 0 {
		t.Errorf("still up while standing down: %v %v", u.managedLinks(), u.files())
	}
	if u.r.Ready() == nil {
		t.Error("ready while standing down")
	}
	delete(cm.Data, StandDownKey)
	if err := u.c.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	u.mustPass()
	if len(u.managedLinks()) != 1 || u.r.Ready() != nil {
		t.Errorf("not rebuilt after the switch was removed: %v %v", u.managedLinks(), u.r.Ready())
	}
}
