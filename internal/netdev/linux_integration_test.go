//go:build linux && integration

package netdev

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// These tests change links in the current network namespace: run them in a
// privileged container (make integration), never on a host.

func ensureVRF(t *testing.T, name string, table uint32) {
	t.Helper()
	if _, err := netlink.LinkByName(name); err == nil {
		return
	}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name}, Table: table}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatal(err)
	}
}

func delLink(name string) {
	if l, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(l)
	}
}

func readSysctl(t *testing.T, link, k string) string {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + link + "/" + k)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestIntegrationLinkLifecycle(t *testing.T) {
	if os.Getenv("DN42_INTEGRATION") != "1" {
		t.Skip("set DN42_INTEGRATION=1, in a privileged container only")
	}
	ensureVRF(t, "vrf-dn42", 42)
	defer delLink("vrf-dn42")
	// A link Talos would own: must never be touched.
	foreign := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: "wg-foreign"}, LinkType: "wireguard"}
	if err := netlink.LinkAdd(foreign); err != nil {
		t.Fatal(err)
	}
	defer delLink("wg-foreign")
	defer delLink("wg-it")

	m := NewLinux()
	priv, pub := key(t), key(t).PublicKey()
	spec := &Spec{
		Name: "wg-it", VRF: "vrf-dn42", PrivateKey: priv, ListenPort: 22189, PeerPublicKey: pub,
		Endpoint: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51820},
		Address:  netip.MustParsePrefix("fe80::3818/64"),
		MTU:      1420,
	}
	now := time.Now()
	plan, err := m.Ensure(spec, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("create: %v", plan.Description)

	st, err := m.Inspect("wg-it")
	if err != nil || st == nil {
		t.Fatal(st, err)
	}
	if !st.Managed() || st.Master != "vrf-dn42" || !st.Up || st.ListenPort != 22189 || st.PrivateKey != priv {
		t.Errorf("state: %+v", st)
	}
	if len(st.Addresses) != 1 || st.Addresses[0] != spec.Address {
		t.Errorf("addresses: %v", st.Addresses)
	}
	if readSysctl(t, "wg-it", "accept_ra") != "0" || readSysctl(t, "wg-it", "accept_redirects") != "0" {
		t.Error("sysctls not set")
	}
	if len(st.Peers) != 1 || st.Peers[0].PublicKey != pub || st.Peers[0].Keepalive != Keepalive ||
		st.Peers[0].Endpoint.String() != "[2001:db8::1]:51820" || len(st.Peers[0].AllowedIPs) != 2 {
		t.Errorf("peer: %+v", st.Peers)
	}

	// Unchanged: empty plan, nothing applied.
	plan, err = m.Ensure(spec, now)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Errorf("second ensure changed: %v", plan.Description)
	}

	// Change port, address and MTU only.
	spec.MTU = 1380
	spec.ListenPort = 22190
	spec.Address = netip.MustParsePrefix("fe80::100/64")
	plan, err = m.Ensure(spec, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("update: %v", plan.Description)
	st, _ = m.Inspect("wg-it")
	if st.ListenPort != 22190 || st.MTU != 1380 || len(st.Addresses) != 1 || st.Addresses[0] != spec.Address {
		t.Errorf("after update: port %d addrs %v", st.ListenPort, st.Addresses)
	}

	// Someone takes it out of the VRF: put back, address still there.
	l, _ := netlink.LinkByName("wg-it")
	if err := netlink.LinkSetNoMaster(l); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(spec, now); err != nil {
		t.Fatal(err)
	}
	st, _ = m.Inspect("wg-it")
	if st.Master != "vrf-dn42" || len(st.Addresses) != 1 {
		t.Errorf("after re-enslave: %+v", st)
	}

	// Only managed links are listed.
	ls, err := m.ListManaged()
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 || ls[0].Name != "wg-it" {
		t.Errorf("managed: %v", ls)
	}

	// Foreign links are refused.
	spec2 := *spec
	spec2.Name = "wg-foreign"
	if _, err := m.Ensure(&spec2, now); !errors.Is(err, ErrNotManaged) {
		t.Errorf("ensure foreign: %v", err)
	}
	if err := m.Delete("wg-foreign"); !errors.Is(err, ErrNotManaged) {
		t.Errorf("delete foreign: %v", err)
	}
	if fl, err := netlink.LinkByName("wg-foreign"); err != nil || fl.Attrs().Alias != "" {
		t.Error("foreign link changed")
	}

	// Missing VRF.
	spec3 := *spec
	spec3.Name = "wg-novrf"
	spec3.VRF = "vrf-none"
	if _, err := m.Ensure(&spec3, now); !errors.Is(err, ErrVRFMissing) {
		t.Errorf("missing vrf: %v", err)
	}
	if l, _ := m.Inspect("wg-novrf"); l != nil {
		t.Error("link created without vrf")
	}

	if err := m.Delete("wg-it"); err != nil {
		t.Fatal(err)
	}
	if l, _ := m.Inspect("wg-it"); l != nil {
		t.Error("not deleted")
	}
}
