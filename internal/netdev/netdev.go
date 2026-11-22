// Package netdev manages the WireGuard links of the peers: create, diff,
// update and delete, touching only links that carry the managed alias.
package netdev

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Alias marks links this operator owns. Links without it are never changed
// or deleted.
const Alias = "managed-by=dn42-operator"

// Keepalive is the persistent keepalive set on every peer.
const Keepalive = 25 * time.Second

// HandshakeFresh is how recent a handshake must be for the tunnel to count as
// up. WireGuard rekeys every 2 minutes while traffic flows; with a 25s
// keepalive there is always traffic.
const HandshakeFresh = 3 * time.Minute

// AllowedIPs on every peer: link-local for BGP, fd00::/8 for DN42 traffic.
var AllowedIPs = []net.IPNet{
	mustCIDR("fe80::/10"),
	mustCIDR("fd00::/8"),
}

// Sysctls set to these values on every managed link.
var Sysctls = map[string]string{
	"accept_ra":        "0",
	"accept_redirects": "0",
}

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

// ErrNotManaged is returned when a link with the wanted name exists but has
// no managed alias (for example a link Talos still owns during migration).
var ErrNotManaged = errors.New("link exists but is not managed by dn42-operator")

// ErrVRFMissing is returned when the VRF doesn't exist. The operator never
// creates it: the VRF is static plumbing owned by Talos.
var ErrVRFMissing = errors.New("vrf does not exist")

// Spec is the desired state of one link.
type Spec struct {
	Name          string
	VRF           string
	PrivateKey    wgtypes.Key
	ListenPort    int
	PeerPublicKey wgtypes.Key
	// Endpoint is the resolved endpoint, nil when the peer has none.
	Endpoint *net.UDPAddr
	// Address is our link-local address, as /64.
	Address netip.Prefix
	// MTU of the link (0: leave as is).
	MTU int
}

// WGPeer is the actual WireGuard peer state.
type WGPeer struct {
	PublicKey     wgtypes.Key
	Endpoint      *net.UDPAddr
	AllowedIPs    []net.IPNet
	Keepalive     time.Duration
	LastHandshake time.Time
}

// State is the actual state of one link.
type State struct {
	Name       string
	Alias      string
	Master     string // name of the master link (VRF), "" if none
	Up         bool
	MTU        int
	Addresses  []netip.Prefix
	Sysctls    map[string]string
	PrivateKey wgtypes.Key
	ListenPort int
	Peers      []WGPeer
}

// Managed reports whether the link carries the managed alias.
func (s *State) Managed() bool { return s.Alias == Alias }

// LastHandshake returns the handshake time of the first peer.
func (s *State) LastHandshake() time.Time {
	if len(s.Peers) == 0 {
		return time.Time{}
	}
	return s.Peers[0].LastHandshake
}

// Plan lists what must change to get from State to Spec. The zero Plan
// changes nothing.
type Plan struct {
	SetAlias    bool
	SetMaster   bool
	SetSysctls  map[string]string
	AddAddrs    []netip.Prefix
	DelAddrs    []netip.Prefix
	SetUp       bool
	SetMTU      int // 0: unchanged
	WireGuard   *wgtypes.Config
	Description []string // human-readable, for logs
}

// Empty reports whether the plan changes nothing.
func (p *Plan) Empty() bool { return len(p.Description) == 0 }

func (p *Plan) add(format string, args ...any) {
	p.Description = append(p.Description, fmt.Sprintf(format, args...))
}

// Diff computes the changes for a link. Only what differs is in the plan, so
// an unchanged peer never flaps. The endpoint is left alone while the
// tunnel has a fresh handshake, so a peer that roamed isn't pulled back.
func Diff(s *State, d *Spec, now time.Time) *Plan {
	p := &Plan{}
	if s.Alias != Alias {
		p.SetAlias = true
		p.add("alias")
	}
	if s.Master != d.VRF {
		p.SetMaster = true
		p.add("master %q -> %q", s.Master, d.VRF)
	}
	for k, v := range Sysctls {
		if s.Sysctls[k] != v {
			if p.SetSysctls == nil {
				p.SetSysctls = map[string]string{}
			}
			p.SetSysctls[k] = v
			p.add("sysctl %s=%s", k, v)
		}
	}
	if !slices.Contains(s.Addresses, d.Address) {
		p.AddAddrs = append(p.AddAddrs, d.Address)
		p.add("add address %s", d.Address)
	}
	for _, a := range s.Addresses {
		if a != d.Address {
			p.DelAddrs = append(p.DelAddrs, a)
			p.add("delete address %s", a)
		}
	}
	if d.MTU != 0 && s.MTU != d.MTU {
		p.SetMTU = d.MTU
		p.add("mtu %d -> %d", s.MTU, d.MTU)
	}
	if !s.Up {
		p.SetUp = true
		p.add("up")
	}

	cfg := wgtypes.Config{}
	changed := false
	if s.PrivateKey != d.PrivateKey {
		k := d.PrivateKey
		cfg.PrivateKey = &k
		changed = true
		p.add("private key")
	}
	if s.ListenPort != d.ListenPort {
		port := d.ListenPort
		cfg.ListenPort = &port
		changed = true
		p.add("listen port %d -> %d", s.ListenPort, d.ListenPort)
	}

	fullPeer := wgtypes.PeerConfig{
		PublicKey:                   d.PeerPublicKey,
		Endpoint:                    d.Endpoint,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  AllowedIPs,
		PersistentKeepaliveInterval: ptr(Keepalive),
	}
	if len(s.Peers) != 1 || s.Peers[0].PublicKey != d.PeerPublicKey {
		cfg.ReplacePeers = true
		cfg.Peers = []wgtypes.PeerConfig{fullPeer}
		changed = true
		p.add("replace peers")
	} else {
		cur := s.Peers[0]
		pc := wgtypes.PeerConfig{PublicKey: d.PeerPublicKey, UpdateOnly: true}
		peerChanged := false
		if !sameNets(cur.AllowedIPs, AllowedIPs) {
			pc.ReplaceAllowedIPs = true
			pc.AllowedIPs = AllowedIPs
			peerChanged = true
			p.add("allowed ips")
		}
		if cur.Keepalive != Keepalive {
			pc.PersistentKeepaliveInterval = ptr(Keepalive)
			peerChanged = true
			p.add("keepalive")
		}
		fresh := !cur.LastHandshake.IsZero() && now.Sub(cur.LastHandshake) < HandshakeFresh
		if d.Endpoint != nil && !sameUDPAddr(cur.Endpoint, d.Endpoint) && !fresh {
			pc.Endpoint = d.Endpoint
			peerChanged = true
			p.add("endpoint %v -> %v", cur.Endpoint, d.Endpoint)
		}
		if peerChanged {
			cfg.Peers = []wgtypes.PeerConfig{pc}
			changed = true
		}
	}
	if changed {
		p.WireGuard = &cfg
	}
	return p
}

func ptr[T any](v T) *T { return &v }

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func sameNets(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]string, len(a))
	bs := make([]string, len(b))
	for i := range a {
		as[i] = a[i].String()
		bs[i] = b[i].String()
	}
	sort.Strings(as)
	sort.Strings(bs)
	return slices.Equal(as, bs)
}

// Manager is the link backend. The Linux implementation uses netlink,
// wgctrl and /proc/sys.
type Manager interface {
	// ListManaged returns the state of every link with the managed alias.
	ListManaged() ([]State, error)
	// Inspect returns the state of a link, or nil if it doesn't exist.
	Inspect(name string) (*State, error)
	// Ensure creates or updates a link to match spec and returns the plan
	// that was applied. It fails with ErrNotManaged for an existing link
	// without the alias, and with ErrVRFMissing if the VRF is missing.
	Ensure(spec *Spec, now time.Time) (*Plan, error)
	// Delete removes a managed link. It refuses links without the alias.
	Delete(name string) error
}
