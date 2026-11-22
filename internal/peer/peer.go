// Package peer turns DN42Peer objects into typed, validated peers. Everything
// that ends up in a WireGuard link or BIRD config comes out of here as a fixed
// type (int, netip.Addr, key, interface name), never as a free-form string.
//
// The checks mirror the CRD schema, so the autopeer web app and the CI gate
// can reuse them, and add the checks across objects the schema can't do.
package peer

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

const (
	// InterfacePrefix is prepended to the peer name for the WireGuard link.
	InterfacePrefix = "wg-"
	// ProtocolPrefix is prepended to the peer name for the BIRD protocol,
	// so a peer name can never collide with a BIRD keyword or with a symbol
	// in bird.conf (bird.conf must not define symbols starting with peer_).
	ProtocolPrefix = "peer_"

	// DefaultMTU is the WireGuard default (1500 minus 80 bytes of IPv6 +
	// WireGuard overhead).
	DefaultMTU = 1420
	MinMTU     = 1280 // IPv6 minimum
	MaxMTU     = 1500

	MinListenPort = 20000
	MaxListenPort = 29999
)

// DefaultLocalLinkLocal is our link-local address when the peer sets none.
var DefaultLocalLinkLocal = netip.MustParseAddr("fe80::3818")

// DefaultLink is used when a peer has no spec.link (measuring is not built yet).
var DefaultLink = dn42v1.LinkValues{Latency: 5, Bandwidth: 24, Crypto: 34}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)
	keyRefRe = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
	// RFC 1123 hostname.
	hostRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// Reasons used in the Valid condition.
const (
	ReasonValid              = "Valid"
	ReasonInvalidSpec        = "InvalidSpec"
	ReasonListenPortRequired = "ListenPortRequired"
	ReasonPortConflict       = "PortConflict"
	ReasonNeighborConflict   = "NeighborConflict"
	ReasonBIRDRejected       = "BIRDRejected"
)

// Peer is a validated DN42Peer.
type Peer struct {
	Name           string // ^[a-z][a-z0-9]{0,11}$
	ASN            uint32
	ListenPort     int
	Endpoint       *Endpoint // nil: no endpoint, we only answer
	PublicKey      wgtypes.Key
	LocalLinkLocal netip.Addr
	MTU            int
	Neighbor       netip.Addr
	Link           dn42v1.LinkValues
	// LinkSet is true when spec.link was given; otherwise Link holds the
	// defaults and the latency may be replaced by a measurement.
	LinkSet bool
	KeyRef  string // "" = the shared autopeer key
}

// Interface is the WireGuard link name.
func (p *Peer) Interface() string { return InterfacePrefix + p.Name }

// Protocol is the BIRD protocol name.
func (p *Peer) Protocol() string { return ProtocolPrefix + p.Name }

// Endpoint is a validated host (IP or hostname) and port.
type Endpoint struct {
	Host string // IP literal (without brackets) or RFC 1123 hostname
	Port int
}

// String formats the endpoint as host:port, with brackets for IPv6.
func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// IsDN42ASN reports whether asn is in one of the ranges DN42 peers use.
func IsDN42ASN(asn int64) bool {
	return (asn >= 4242420000 && asn <= 4242429999) ||
		(asn >= 4201000000 && asn <= 4201999999) ||
		(asn >= 64512 && asn <= 65534) ||
		(asn >= 76100 && asn <= 76199)
}

// DefaultListenPort returns "2" followed by the last 4 digits of the ASN, for
// 424242xxxx ASNs only. For other ASNs there is no sane default (it would
// collide or not fit the range), so the peer must set listenPort.
func DefaultListenPort(asn int64) (int, bool) {
	if asn >= 4242420000 && asn <= 4242429999 {
		return MinListenPort + int(asn%10000), true
	}
	return 0, false
}

// Error is a validation error with a condition reason.
type Error struct {
	Reason  string
	Message string
}

func (e *Error) Error() string { return e.Message }

func invalid(format string, args ...any) *Error {
	return &Error{Reason: ReasonInvalidSpec, Message: fmt.Sprintf(format, args...)}
}

// ValidateName checks a peer (object) name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return invalid("name %q must match %s", name, nameRe)
	}
	return nil
}

// FromObject validates one DN42Peer on its own and returns the typed peer.
func FromObject(o *dn42v1.DN42Peer) (*Peer, *Error) {
	return FromSpec(o.Name, &o.Spec)
}

// FromSpec validates a spec on its own and returns the typed peer.
func FromSpec(name string, s *dn42v1.DN42PeerSpec) (*Peer, *Error) {
	p := &Peer{Name: name}
	if err := ValidateName(name); err != nil {
		return nil, err.(*Error)
	}
	if !IsDN42ASN(s.ASN) {
		return nil, invalid("asn %d is not in a DN42 range", s.ASN)
	}
	p.ASN = uint32(s.ASN)

	if s.ListenPort != nil {
		port := int(*s.ListenPort)
		if port < MinListenPort || port > MaxListenPort {
			return nil, invalid("listenPort %d is outside %d-%d", port, MinListenPort, MaxListenPort)
		}
		p.ListenPort = port
	} else if port, ok := DefaultListenPort(s.ASN); ok {
		p.ListenPort = port
	} else {
		return nil, &Error{Reason: ReasonListenPortRequired,
			Message: fmt.Sprintf("asn %d is not a 424242xxxx ASN, so there is no default port; set spec.listenPort", s.ASN)}
	}

	if s.Endpoint != "" {
		ep, err := ParseEndpoint(s.Endpoint)
		if err != nil {
			return nil, invalid("endpoint: %v", err)
		}
		p.Endpoint = ep
	}

	key, err := ParseKey(s.PublicKey)
	if err != nil {
		return nil, invalid("publicKey: %v", err)
	}
	p.PublicKey = key

	p.MTU = DefaultMTU
	if s.MTU != nil {
		if *s.MTU < MinMTU || *s.MTU > MaxMTU {
			return nil, invalid("mtu %d is outside %d-%d", *s.MTU, MinMTU, MaxMTU)
		}
		p.MTU = int(*s.MTU)
	}

	p.LocalLinkLocal = DefaultLocalLinkLocal
	if s.LocalLinkLocal != "" {
		a, err := ParseLinkLocal(s.LocalLinkLocal)
		if err != nil {
			return nil, invalid("localLinkLocal: %v", err)
		}
		p.LocalLinkLocal = a
	}
	a, err := ParseLinkLocal(s.Neighbor)
	if err != nil {
		return nil, invalid("neighbor: %v", err)
	}
	p.Neighbor = a
	if p.Neighbor == p.LocalLinkLocal {
		return nil, invalid("neighbor %s is our own address on the link", p.Neighbor)
	}

	p.Link = DefaultLink
	if s.Link != nil {
		l := *s.Link
		if l.Latency < 1 || l.Latency > 9 {
			return nil, invalid("link.latency %d is outside 1-9", l.Latency)
		}
		if l.Bandwidth < 21 || l.Bandwidth > 25 {
			return nil, invalid("link.bandwidth %d is outside 21-25", l.Bandwidth)
		}
		if l.Crypto < 31 || l.Crypto > 34 {
			return nil, invalid("link.crypto %d is outside 31-34", l.Crypto)
		}
		p.Link = l
		p.LinkSet = true
	}

	if s.KeyRef != "" {
		if !keyRefRe.MatchString(s.KeyRef) {
			return nil, invalid("keyRef %q is not a valid Secret key", s.KeyRef)
		}
		p.KeyRef = s.KeyRef
	}
	return p, nil
}

// ApplyMeasuredLatency uses a measured latency community when the spec has
// no link values. Out-of-range values are ignored.
func (p *Peer) ApplyMeasuredLatency(lat *int32) {
	if p.LinkSet || lat == nil || *lat < 1 || *lat > 9 {
		return
	}
	p.Link.Latency = *lat
}

// ParseKey parses a base64 WireGuard key.
func ParseKey(s string) (wgtypes.Key, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("not base64")
	}
	if len(b) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("is %d bytes, want %d", len(b), wgtypes.KeyLen)
	}
	return wgtypes.NewKey(b)
}

// ParseLinkLocal parses an IPv6 link-local unicast address without zone.
func ParseLinkLocal(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	if !a.Is6() || a.Is4In6() || !a.IsLinkLocalUnicast() || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv6 link-local address (fe80::/10)", s)
	}
	return a, nil
}

// ParseEndpoint parses host:port, [v6]:port or v4:port.
func ParseEndpoint(s string) (*Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%q: bad port", s)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("%q: not a unicast address", s)
		}
		if a.Is6() && !strings.HasPrefix(s, "[") {
			return nil, fmt.Errorf("%q: IPv6 needs brackets", s)
		}
		return &Endpoint{Host: a.String(), Port: port}, nil
	}
	if len(host) > 253 || !hostRe.MatchString(host) {
		return nil, fmt.Errorf("%q: host is neither an IP nor a hostname", s)
	}
	return &Endpoint{Host: strings.ToLower(host), Port: port}, nil
}

// Result is the outcome of validating one object within the whole set.
type Result struct {
	Object *dn42v1.DN42Peer
	Peer   *Peer  // nil when Err is set
	Err    *Error // why the peer is invalid
}

// ValidateSet validates every object on its own and then across objects:
// duplicate listen ports and duplicate ASN+neighbor. Of two conflicting
// objects the newer one (later creationTimestamp, then name) is invalid, so
// an existing peer is never broken by a new one. Results are sorted by name.
func ValidateSet(objs []dn42v1.DN42Peer) []Result {
	results := make([]Result, len(objs))
	for i := range objs {
		o := &objs[i]
		p, err := FromObject(o)
		results[i] = Result{Object: o, Peer: p, Err: err}
	}

	// Oldest first, so the first claimant of a port keeps it.
	order := make([]int, len(results))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		oa, ob := results[order[a]].Object, results[order[b]].Object
		ta, tb := oa.CreationTimestamp.Time, ob.CreationTimestamp.Time
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		return oa.Name < ob.Name
	})

	type asnNeighbor struct {
		asn uint32
		n   netip.Addr
	}
	ports := map[int]string{}
	neighbors := map[asnNeighbor]string{}
	for _, i := range order {
		r := &results[i]
		if r.Peer == nil {
			continue
		}
		if other, ok := ports[r.Peer.ListenPort]; ok {
			r.Err = &Error{Reason: ReasonPortConflict,
				Message: fmt.Sprintf("listen port %d is already used by peer %s", r.Peer.ListenPort, other)}
			r.Peer = nil
			continue
		}
		k := asnNeighbor{r.Peer.ASN, r.Peer.Neighbor}
		if other, ok := neighbors[k]; ok {
			r.Err = &Error{Reason: ReasonNeighborConflict,
				Message: fmt.Sprintf("AS%d with neighbor %s is already peer %s", k.asn, k.n, other)}
			r.Peer = nil
			continue
		}
		ports[r.Peer.ListenPort] = r.Object.Name
		neighbors[k] = r.Object.Name
	}

	sort.Slice(results, func(a, b int) bool { return results[a].Object.Name < results[b].Object.Name })
	return results
}
