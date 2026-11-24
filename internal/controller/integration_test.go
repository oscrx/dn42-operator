//go:build linux && integration

package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/latency"
	"github.com/oscrx/dn42-operator/internal/netdev"
)

// End to end in one privileged container: our side has vrf-dn42, a real
// BIRD and the operator's links; a "remote" network namespace behind a veth
// plays the peer with its own WireGuard link and BIRD. The test checks the
// handshake and that BGP reaches Established through the VRF.

const ourBird = `
router id 10.0.0.1;
log "%[1]s/bird.log" all;
protocol device { scan time 1; }
function dn42_import(int lat; int bw; int crypto) -> bool { return true; }
function dn42_export(int lat; int bw; int crypto) -> bool { return source ~ [RTS_STATIC, RTS_BGP]; }
protocol static { ipv6; route fd42:4242:1::/48 unreachable; }
template bgp dnpeers {
  vrf "vrf-dn42";
  local as 4242423818;
  path metric on;
  connect delay time 1;
  connect retry time 2;
  error wait time 1, 2;
  ipv6 { import table on; import limit 9000 action block; };
}
include "%[1]s/peers/*.conf";
`

const remoteBird = `
router id 10.0.0.2;
log "%[1]s/remote.log" all;
protocol device { scan time 1; }
protocol static { ipv6; route fd42:4242:2::/48 unreachable; route fd42:4242:3::/48 unreachable; }
protocol bgp op {
  local as 4242420002;
  neighbor fe80::2 as 4242423818;  # our side uses a fixed link-local, like zz
  interface "wg-remote";
  connect delay time 1;
  connect retry time 2;
  error wait time 1, 2;
  ipv6 { import all; export all; };
}
`

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func startBird(t *testing.T, netns, conf, sock string) {
	t.Helper()
	args := []string{"bird", "-f", "-c", conf, "-s", sock}
	if netns != "" {
		args = append([]string{"ip", "netns", "exec", netns}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("bird %s did not start", conf)
}

func waitFor(t *testing.T, what string, timeout time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestIntegrationEndToEnd(t *testing.T) {
	if os.Getenv("DN42_INTEGRATION") != "1" {
		t.Skip("set DN42_INTEGRATION=1, in a privileged container only")
	}
	ctx := context.Background()
	work := t.TempDir()
	peersDir := filepath.Join(work, "peers")
	if err := os.Mkdir(peersDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Our side: the static plumbing Talos owns.
	sh(t, "ip", "link", "add", "vrf-dn42", "type", "vrf", "table", "42")
	sh(t, "ip", "link", "set", "vrf-dn42", "up")
	sh(t, "ip", "link", "add", "dn42-lo", "type", "dummy")
	sh(t, "ip", "link", "set", "dn42-lo", "master", "vrf-dn42", "up")
	// A tunnel Talos still owns: must survive everything.
	sh(t, "ip", "link", "add", "wg-talos", "type", "wireguard")
	sh(t, "ip", "link", "set", "wg-talos", "master", "vrf-dn42")
	t.Cleanup(func() {
		for _, l := range []string{"vrf-dn42", "dn42-lo", "wg-talos", "veth-op", "wg-remote", "wg-aa", "wg-bb"} {
			_ = exec.Command("ip", "link", "del", l).Run()
		}
		_ = exec.Command("ip", "netns", "del", "remote").Run()
	})

	// Remote side.
	sh(t, "ip", "netns", "add", "remote")
	sh(t, "ip", "link", "add", "veth-op", "type", "veth", "peer", "name", "veth-remote")
	sh(t, "ip", "link", "set", "veth-remote", "netns", "remote")
	sh(t, "ip", "addr", "add", "192.0.2.1/24", "dev", "veth-op")
	sh(t, "ip", "link", "set", "veth-op", "up")
	sh(t, "ip", "-n", "remote", "addr", "add", "192.0.2.2/24", "dev", "veth-remote")
	sh(t, "ip", "-n", "remote", "link", "set", "veth-remote", "up")
	sh(t, "ip", "-n", "remote", "link", "set", "lo", "up")
	sh(t, "ip", "addr", "add", "2001:db8:42::1/64", "dev", "veth-op", "nodad")
	sh(t, "ip", "-n", "remote", "addr", "add", "2001:db8:42::2/64", "dev", "veth-remote", "nodad")

	ourKey, remoteKey := genKey(t), genKey(t)
	sh(t, "ip", "-n", "remote", "link", "add", "wg-remote", "type", "wireguard")
	configureRemoteWG(t, remoteKey, ourKey.PublicKey())
	sh(t, "ip", "-n", "remote", "addr", "add", "fe80::1/64", "dev", "wg-remote")
	sh(t, "ip", "-n", "remote", "link", "set", "wg-remote", "up")

	if err := os.WriteFile(filepath.Join(work, "bird.conf"), []byte(fmt.Sprintf(ourBird, work)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "remote.conf"), []byte(fmt.Sprintf(remoteBird, work)), 0o644); err != nil {
		t.Fatal(err)
	}
	ourSock, remoteSock := filepath.Join(work, "bird.ctl"), filepath.Join(work, "remote.ctl")
	startBird(t, "", filepath.Join(work, "bird.conf"), ourSock)
	startBird(t, "remote", filepath.Join(work, "remote.conf"), remoteSock)
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(work, "bird.log"))
			t.Logf("bird.log:\n%s", b)
			b, _ = os.ReadFile(filepath.Join(work, "remote.log"))
			t.Logf("remote.log:\n%s", b)
		}
	})

	bc := &bird.Client{Socket: ourSock, Timeout: 10 * time.Second}
	secret := keySecret(t)
	secret.Data["autopeer"] = []byte(ourKey.String())
	aa := mkPeer("aa", 4242420002, 0, "fe80::1", 0)
	aa.Spec.Endpoint = "192.0.2.2:51820"
	aa.Spec.PublicKey = remoteKey.PublicKey().String()
	aa.Spec.LocalLinkLocal = "fe80::2"
	mtu := int32(1380)
	aa.Spec.MTU = &mtu
	aa.Spec.Link = &dn42v1.LinkValues{Latency: 1, Bandwidth: 25, Crypto: 34}
	nd := netdev.NewLinux()
	h := newHarness(t, nd, &bird.Dir{Path: peersDir, Bird: bc}, bc, aa, secret, endpointService())

	// Create.
	h.mustPass()
	st, err := nd.Inspect("wg-aa")
	if err != nil || st == nil || !st.Managed() || st.Master != "vrf-dn42" || st.ListenPort != 20002 {
		t.Fatalf("wg-aa: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(peersDir, "aa.conf")); err != nil {
		t.Fatal("aa.conf not written")
	}
	if st.MTU != 1380 || len(st.Addresses) != 1 || st.Addresses[0].String() != "fe80::2/64" {
		t.Fatalf("wg-aa mtu %d addresses %v", st.MTU, st.Addresses)
	}

	waitFor(t, "handshake", 30*time.Second, func() bool {
		st, _ := nd.Inspect("wg-aa")
		return st != nil && !st.LastHandshake().IsZero()
	})
	waitFor(t, "BGP Established", 90*time.Second, func() bool {
		ps, err := bc.ShowProtocols(ctx)
		return err == nil && ps["peer_aa"].BGPState == "Established" && ps["peer_aa"].RoutesImported == 2
	})
	if err := h.r.UpdateStatus(ctx); err != nil {
		t.Fatal(err)
	}
	p := h.peer("aa")
	if p.Status.BGPState != "Established" || p.Status.RoutesImported == nil || *p.Status.RoutesImported != 2 || p.Status.LastHandshake == nil {
		t.Errorf("status: %+v", p.Status)
	}
	for _, typ := range []string{dn42v1.ConditionValid, dn42v1.ConditionTunnelReady, dn42v1.ConditionSessionEstablished} {
		if c := h.cond("aa", typ); c.Status != metav1.ConditionTrue {
			t.Errorf("%s: %+v", typ, c)
		}
	}
	// The route from the peer is in BIRD; the session is in the VRF (BGP
	// would not come up on the link-local otherwise).
	t.Logf("aa: state %s, %d routes", p.Status.BGPState, *p.Status.RoutesImported)

	// Latency: real ICMP to the peer's endpoint, v4 and v6, over the
	// underlay (not the VRF).
	for _, a := range []string{"192.0.2.2", "2001:db8:42::2"} {
		rtt, lat, err := latency.Measure(ctx, latency.ICMP{Timeout: time.Second}, netip.MustParseAddr(a), 10, 20*time.Millisecond)
		if err != nil || lat != 1 || rtt <= 0 {
			t.Errorf("ping %s: rtt %v community %d err %v", a, rtt, lat, err)
		} else {
			t.Logf("ping %s: median %v, community %d", a, rtt, lat)
		}
	}

	// Unchanged pass: BIRD isn't reconfigured, the session stays up.
	h.mustPass()
	ps, _ := bc.ShowProtocols(ctx)
	if ps["peer_aa"].BGPState != "Established" {
		t.Error("session dropped on an unchanged pass")
	}

	// Change: link values change only the BIRD snippet.
	p.Spec.Link.Latency = 3
	if err := h.c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	h.mustPass()
	b, _ := os.ReadFile(filepath.Join(peersDir, "aa.conf"))
	if !strings.Contains(string(b), "dn42_import(3, 25, 34)") {
		t.Errorf("aa.conf not updated:\n%s", b)
	}

	// A second peer with a template BIRD doesn't know: rejected by
	// configure check, aa keeps working, bb is Valid=False.
	bb := mkPeer("bb", 4242420003, 0, "fe80::3", 1)
	h.create(bb)
	h.r.Renderer.Template = "nosuchtemplate"
	h.mustPass()
	h.r.Renderer.Template = "dnpeers"
	if err := h.r.UpdateStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if c := h.cond("bb", dn42v1.ConditionValid); c.Status != metav1.ConditionFalse || c.Reason != "BIRDRejected" {
		t.Errorf("bb: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(peersDir, "bb.conf")); err == nil {
		t.Error("rejected bb.conf left in place")
	}
	ps, _ = bc.ShowProtocols(ctx)
	if ps["peer_aa"].BGPState != "Established" {
		t.Error("aa dropped while bb was rejected")
	}
	// With the right template bb goes through.
	h.mustPass()
	ps, _ = bc.ShowProtocols(ctx)
	if _, ok := ps["peer_bb"]; !ok {
		t.Error("peer_bb not in bird")
	}

	// API outage: nothing changes.
	h.listOK = false
	if err := h.pass(); err == nil {
		t.Error("pass succeeded during outage")
	}
	h.listOK = true
	if l, _ := nd.ListManaged(); len(l) != 2 {
		t.Errorf("links changed during outage: %d", len(l))
	}

	// Delete bb: link, snippet and BIRD protocol go, aa stays.
	h.delete(bb)
	h.mustPass()
	if l, _ := nd.Inspect("wg-bb"); l != nil {
		t.Error("wg-bb not deleted")
	}
	ps, _ = bc.ShowProtocols(ctx)
	if _, ok := ps["peer_bb"]; ok {
		t.Error("peer_bb still in bird")
	}
	if ps["peer_aa"].BGPState != "Established" {
		t.Error("aa dropped when bb was deleted")
	}

	// Follower: everything managed goes, BIRD keeps only its static config.
	h.r.State.Set(RoleFollower)
	h.mustPass()
	if l, _ := nd.ListManaged(); len(l) != 0 {
		t.Errorf("follower kept links: %v", l)
	}
	ps, _ = bc.ShowProtocols(ctx)
	if _, ok := ps["peer_aa"]; ok {
		t.Error("follower kept peer_aa in bird")
	}

	// The Talos-owned links were never touched.
	for _, l := range []string{"wg-talos", "dn42-lo"} {
		st, err := nd.Inspect(l)
		if err != nil || st == nil || st.Managed() || st.Master != "vrf-dn42" {
			t.Errorf("%s changed: %+v %v", l, st, err)
		}
	}
}

// configureRemoteWG sets up wg-remote in the "remote" namespace through
// wgctrl. Not with wg(8): hosts with an AppArmor profile for wg (Ubuntu
// 26.04 runners) confine it in the container too, so it can't read a key
// file outside /etc/wireguard.
func configureRemoteWG(t *testing.T, key wgtypes.Key, peerKey wgtypes.Key) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	remote, err := netns.GetFromName("remote")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	if err := netns.Set(remote); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			panic(err) // the thread is unusable in the wrong namespace
		}
	}()
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	port := 51820
	allowed := []string{"fe80::/10", "fd00::/8"}
	var ips []net.IPNet
	for _, a := range allowed {
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, *n)
	}
	if err := c.ConfigureDevice("wg-remote", wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
		Peers:      []wgtypes.PeerConfig{{PublicKey: peerKey, AllowedIPs: ips}},
	}); err != nil {
		t.Fatal(err)
	}
}
