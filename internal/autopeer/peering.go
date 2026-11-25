package autopeer

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"text/template"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/peer"
)

// Request is what the peer submits in the form.
type Request struct {
	ASN       int64
	Name      string // becomes the DN42Peer name, wg-<name>
	PublicKey string
	Endpoint  string // optional host:port
	Neighbor  string // their link-local
	MTU       int32  // 0: the default
}

// Suggest pre-fills the new-peering form: the name from the login's mntner
// (OSCRX-MNT -> oscrx) and the link-local fe80::<last 4 digits of the ASN>.
// Either is empty when there's nothing sensible to suggest.
func Suggest(cfg *Config, id *Identity) (name, neighbor string) {
	if id.Admin {
		return "", "" // acting for someone else
	}
	n := strings.ToLower(strings.TrimSuffix(strings.ToUpper(id.DisplayName()), "-MNT"))
	n = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, n)
	if len(n) > 12 {
		n = n[:12]
	}
	if peer.ValidateName(n) == nil {
		name = n
	}
	for _, asn := range id.ASNs {
		if asn != cfg.Router.ASN {
			if a, err := netip.ParseAddr(fmt.Sprintf("fe80::%04d", asn%10000)); err == nil {
				neighbor = a.String()
			}
			break
		}
	}
	return name, neighbor
}

// FieldError is a validation error for one form field.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

// notYours says why id may not manage asn: for an admin it isn't a DN42 ASN
// at all (often something else pasted into the field); for anyone else it
// isn't among the ASNs their login maintains.
func notYours(id *Identity, asn int64) string {
	if id.Admin {
		return fmt.Sprintf("AS%d is not a DN42 ASN; check the number", asn)
	}
	own := make([]string, len(id.ASNs))
	for i, a := range id.ASNs {
		own[i] = fmt.Sprintf("AS%d", a)
	}
	return fmt.Sprintf("you may not manage AS%d; this login maintains %s", asn, strings.Join(own, ", "))
}

// BuildPeer turns a request into a DN42Peer, checked on its own and against
// the existing peers (name, port, ASN+neighbor). It always writes an
// explicit listenPort: the 2+last-4-digits default when that is free,
// otherwise the highest free port, so the CI gate and the operator never
// have to guess.
func BuildPeer(cfg *Config, id *Identity, req *Request, existing []dn42v1.DN42Peer) (*dn42v1.DN42Peer, *peer.Peer, error) {
	if !id.May(req.ASN) {
		return nil, nil, &FieldError{"asn", notYours(id, req.ASN)}
	}
	// Same ASN on both ends is iBGP: BIRD makes it multihop, which can't
	// use a link-local neighbor, and it's no DN42 peering anyway.
	if req.ASN == cfg.Router.ASN {
		return nil, nil, &FieldError{"asn", fmt.Sprintf("AS%d is this router's own ASN", req.ASN)}
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if err := peer.ValidateName(name); err != nil {
		return nil, nil, &FieldError{"name", "use 1-12 lowercase letters and digits, starting with a letter"}
	}
	used := map[int]bool{}
	for i := range existing {
		e := &existing[i]
		if e.Name == name {
			return nil, nil, &FieldError{"name", fmt.Sprintf("%q is already taken", name)}
		}
		if p, err := peer.FromObject(e); err == nil {
			used[p.ListenPort] = true
		} else if e.Spec.ListenPort != nil {
			used[int(*e.Spec.ListenPort)] = true
		}
	}
	port := 0
	if d, ok := peer.DefaultListenPort(req.ASN); ok && !used[d] {
		port = d
	} else {
		for p := peer.MaxListenPort; p >= peer.MinListenPort; p-- {
			if !used[p] {
				port = p
				break
			}
		}
	}
	if port == 0 {
		return nil, nil, &FieldError{"asn", "no free tunnel port left"}
	}
	p32 := int32(port)
	obj := &dn42v1.DN42Peer{
		TypeMeta:   metav1.TypeMeta{APIVersion: dn42v1.GroupVersion.String(), Kind: "DN42Peer"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cfg.Kubernetes.Namespace},
		Spec: dn42v1.DN42PeerSpec{
			ASN:        req.ASN,
			ListenPort: &p32,
			Endpoint:   strings.TrimSpace(req.Endpoint),
			PublicKey:  strings.TrimSpace(req.PublicKey),
			Neighbor:   strings.TrimSpace(req.Neighbor),
			MTU:        mtuPtr(req.MTU),
		},
	}
	pp, verr := peer.FromObject(obj)
	if verr != nil {
		return nil, nil, &FieldError{fieldFor(verr.Message), verr.Message}
	}
	if pp.Neighbor == cfg.routerLinkLocal() {
		return nil, nil, &FieldError{"neighbor", fmt.Sprintf("%s is our address; pick another link-local address", pp.Neighbor)}
	}
	// Cross-object checks exactly as the operator runs them, with the new
	// object as the newest.
	all := append(append([]dn42v1.DN42Peer(nil), existing...), *obj)
	all[len(all)-1].CreationTimestamp = metav1.NewTime(time.Now().Add(100 * 365 * 24 * time.Hour))
	for _, r := range peer.ValidateSet(all) {
		if r.Object.Name == name && r.Err != nil {
			return nil, nil, &FieldError{fieldFor(r.Err.Message), r.Err.Message}
		}
	}
	return obj, pp, nil
}

func fieldFor(msg string) string {
	for _, f := range []string{"endpoint", "publicKey", "neighbor", "listen port", "asn", "mtu"} {
		if strings.Contains(msg, f) {
			return strings.Fields(f)[0]
		}
	}
	return "form"
}

// PeerFileName is peers/<asn>-<name>.yaml.
func PeerFileName(dir string, o *dn42v1.DN42Peer) string {
	return fmt.Sprintf("%s/%d-%s.yaml", strings.TrimRight(dir, "/"), o.Spec.ASN, o.Name)
}

// PeerYAML renders the peer file. Only typed spec fields are written; the
// namespace comes from the ArgoCD Application, not the file.
func PeerYAML(o *dn42v1.DN42Peer) ([]byte, error) {
	out := struct {
		APIVersion string              `json:"apiVersion"`
		Kind       string              `json:"kind"`
		Metadata   map[string]string   `json:"metadata"`
		Spec       dn42v1.DN42PeerSpec `json:"spec"`
	}{dn42v1.GroupVersion.String(), "DN42Peer", map[string]string{"name": o.Name}, o.Spec}
	b, err := yaml.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append([]byte(fmt.Sprintf("# AS%d, submitted through autopeer.\n", o.Spec.ASN)), b...), nil
}

// PeerSide is the config the peer applies on their side.
type PeerSide struct {
	Interface string
	WireGuard string
	BIRD      string
}

var wgTmpl = template.Must(template.New("wg").Parse(`# /etc/wireguard/{{.Iface}}.conf
[Interface]
PrivateKey = <your private key for public key {{.TheirKey}}>
ListenPort = {{.TheirPort}}
MTU = {{.MTU}}
Table = off
PostUp = ip addr add {{.Neighbor}}/64 dev %i
PostUp = sysctl -w net.ipv6.conf.%i.autoconf=0

[Peer]
PublicKey = {{.OurKey}}
Endpoint = {{.OurEndpoint}}
AllowedIPs = fe80::/10, fd00::/8
PersistentKeepalive = 25
`))

var birdTmpl = template.Must(template.New("bird").Parse(`# BIRD 2, with your usual DN42 peer template
protocol bgp {{.Proto}} from dnpeers {
  neighbor {{.OurLinkLocal}} as {{.OurASN}};
  interface "{{.Iface}}";
}
`))

// RenderPeerSide renders the peer's WireGuard and BIRD config. ourKey is our
// public key on this link (from the peer's status; the shared key until it
// is live). Every value comes from validated typed fields.
func RenderPeerSide(cfg *Config, p *peer.Peer, ourKey wgtypes.Key) (*PeerSide, error) {
	iface := "dn42-" + cfg.Router.Name // <= 15 chars: router name is <= 12
	if len(iface) > 15 {
		iface = iface[:15]
	}
	// Their listen port: the one in the endpoint they gave us, else the
	// convention of 2 + the last 4 digits of our ASN.
	theirPort := p.ListenPort
	if p.Endpoint != nil {
		theirPort = p.Endpoint.Port
	} else if d, ok := peer.DefaultListenPort(cfg.Router.ASN); ok {
		theirPort = d
	}
	data := map[string]any{
		"Iface":        iface,
		"TheirKey":     p.PublicKey.String(),
		"TheirPort":    theirPort,
		"Neighbor":     p.Neighbor.String(),
		"OurKey":       ourKey.String(),
		"MTU":          p.MTU,
		"OurEndpoint":  joinHostPort(cfg.Router.EndpointHost, p.ListenPort),
		"OurLinkLocal": cfg.routerLinkLocal().String(),
		"OurASN":       cfg.Router.ASN,
		"Proto":        "dn42_" + cfg.Router.Name,
	}
	var wg, bird bytes.Buffer
	if err := wgTmpl.Execute(&wg, data); err != nil {
		return nil, err
	}
	if err := birdTmpl.Execute(&bird, data); err != nil {
		return nil, err
	}
	return &PeerSide{Interface: iface, WireGuard: wg.String(), BIRD: bird.String()}, nil
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// UpdatePeer changes the peer-controlled fields of an existing autopeer
// (public key, endpoint, link-local). Name, ASN, listen port and link
// values stay. others are all other known peers (repo and pending).
func UpdatePeer(cfg *Config, id *Identity, cur *dn42v1.DN42Peer, req *Request, others []dn42v1.DN42Peer) (*dn42v1.DN42Peer, *peer.Peer, error) {
	if !id.May(cur.Spec.ASN) {
		return nil, nil, &FieldError{"asn", notYours(id, cur.Spec.ASN)}
	}
	// A keyRef (the peer's own key on our side) is kept as it is: DeepCopy.
	obj := cur.DeepCopy()
	obj.Spec.PublicKey = strings.TrimSpace(req.PublicKey)
	obj.Spec.Endpoint = strings.TrimSpace(req.Endpoint)
	obj.Spec.Neighbor = strings.TrimSpace(req.Neighbor)
	obj.Spec.MTU = mtuPtr(req.MTU)
	if specEqual(obj, cur) {
		return nil, nil, &FieldError{"form", "nothing changed"}
	}
	pp, verr := peer.FromObject(obj)
	if verr != nil {
		return nil, nil, &FieldError{fieldFor(verr.Message), verr.Message}
	}
	if pp.Neighbor == cfg.routerLinkLocal() {
		return nil, nil, &FieldError{"neighbor", fmt.Sprintf("%s is our address; pick another link-local address", pp.Neighbor)}
	}
	var all []dn42v1.DN42Peer
	for i := range others {
		if others[i].Name != cur.Name {
			all = append(all, others[i])
		}
	}
	all = append(all, *obj)
	all[len(all)-1].CreationTimestamp = metav1.NewTime(time.Now().Add(100 * 365 * 24 * time.Hour))
	for _, r := range peer.ValidateSet(all) {
		if r.Object.Name == obj.Name && r.Err != nil {
			return nil, nil, &FieldError{fieldFor(r.Err.Message), r.Err.Message}
		}
	}
	return obj, pp, nil
}

func specEqual(a, b *dn42v1.DN42Peer) bool {
	return a.Spec.PublicKey == b.Spec.PublicKey && a.Spec.Endpoint == b.Spec.Endpoint &&
		a.Spec.Neighbor == b.Spec.Neighbor && mtuOf(a) == mtuOf(b)
}

// mtuPtr is spec.mtu for a form value: unset for 0 (the default).
func mtuPtr(m int32) *int32 {
	if m == 0 {
		return nil
	}
	return &m
}

func mtuOf(o *dn42v1.DN42Peer) int32 {
	if o.Spec.MTU == nil {
		return 0
	}
	return *o.Spec.MTU
}
