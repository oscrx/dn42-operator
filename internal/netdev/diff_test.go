package netdev

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func key(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func setup(t *testing.T) (*State, *Spec) {
	priv, pub := key(t), key(t).PublicKey()
	ep := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51820}
	addr := netip.MustParsePrefix("fe80::3818/64")
	spec := &Spec{Name: "wg-x", VRF: "vrf-dn42", PrivateKey: priv, ListenPort: 22189,
		PeerPublicKey: pub, Endpoint: ep, Address: addr}
	st := &State{Name: "wg-x", Alias: Alias, Master: "vrf-dn42", Up: true,
		Addresses: []netip.Prefix{addr}, Sysctls: map[string]string{"accept_ra": "0", "accept_redirects": "0"},
		PrivateKey: priv, ListenPort: 22189,
		Peers: []WGPeer{{PublicKey: pub, Endpoint: ep, AllowedIPs: AllowedIPs, Keepalive: Keepalive}}}
	return st, spec
}

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func TestDiffNoop(t *testing.T) {
	st, spec := setup(t)
	if p := Diff(st, spec, now); !p.Empty() || p.WireGuard != nil {
		t.Errorf("unchanged link has changes: %v", p.Description)
	}
	// Allowed IPs in another order are the same.
	st.Peers[0].AllowedIPs = []net.IPNet{AllowedIPs[1], AllowedIPs[0]}
	if p := Diff(st, spec, now); !p.Empty() {
		t.Errorf("reordered allowed ips: %v", p.Description)
	}
}

func TestDiffNewLink(t *testing.T) {
	_, spec := setup(t)
	st := &State{Name: "wg-x", Alias: Alias, Sysctls: map[string]string{"accept_ra": "1", "accept_redirects": "1"}}
	p := Diff(st, spec, now)
	if !p.SetMaster || !p.SetUp || len(p.AddAddrs) != 1 || len(p.SetSysctls) != 2 || p.SetAlias {
		t.Errorf("%+v", p)
	}
	wg := p.WireGuard
	if wg == nil || !wg.ReplacePeers || len(wg.Peers) != 1 || wg.PrivateKey == nil || *wg.ListenPort != 22189 {
		t.Fatalf("%+v", wg)
	}
	pc := wg.Peers[0]
	if pc.Endpoint == nil || *pc.PersistentKeepaliveInterval != Keepalive || !pc.ReplaceAllowedIPs || len(pc.AllowedIPs) != 2 {
		t.Errorf("%+v", pc)
	}
}

func TestDiffEndpointRoaming(t *testing.T) {
	st, spec := setup(t)
	st.Peers[0].Endpoint = &net.UDPAddr{IP: net.ParseIP("2001:db8::99"), Port: 1234}
	// Fresh handshake: the peer roamed, leave it.
	st.Peers[0].LastHandshake = now.Add(-time.Minute)
	if p := Diff(st, spec, now); !p.Empty() {
		t.Errorf("roamed endpoint reset: %v", p.Description)
	}
	// Stale: go back to the configured endpoint, update only.
	st.Peers[0].LastHandshake = now.Add(-10 * time.Minute)
	p := Diff(st, spec, now)
	if p.WireGuard == nil || p.WireGuard.ReplacePeers || !p.WireGuard.Peers[0].UpdateOnly ||
		p.WireGuard.Peers[0].Endpoint.String() != "[2001:db8::1]:51820" {
		t.Errorf("%+v", p.WireGuard)
	}
	// No endpoint in the spec: never touched.
	spec.Endpoint = nil
	if p := Diff(st, spec, now); !p.Empty() {
		t.Errorf("%v", p.Description)
	}
}

func TestDiffChanges(t *testing.T) {
	st, spec := setup(t)
	spec.PeerPublicKey = key(t).PublicKey()
	p := Diff(st, spec, now)
	if p.WireGuard == nil || !p.WireGuard.ReplacePeers || p.WireGuard.PrivateKey != nil {
		t.Errorf("pubkey change: %+v", p.WireGuard)
	}

	st, spec = setup(t)
	spec.ListenPort = 22190
	spec.Address = netip.MustParsePrefix("fe80::100/64")
	p = Diff(st, spec, now)
	if p.WireGuard == nil || *p.WireGuard.ListenPort != 22190 || len(p.WireGuard.Peers) != 0 {
		t.Errorf("port: %+v", p.WireGuard)
	}
	if len(p.AddAddrs) != 1 || len(p.DelAddrs) != 1 || p.DelAddrs[0].String() != "fe80::3818/64" {
		t.Errorf("addrs: %v %v", p.AddAddrs, p.DelAddrs)
	}

	st, spec = setup(t)
	st.Peers[0].Keepalive = 0
	st.Master = ""
	p = Diff(st, spec, now)
	if !p.SetMaster || p.WireGuard == nil || p.WireGuard.Peers[0].PersistentKeepaliveInterval == nil {
		t.Errorf("%+v", p)
	}
}
