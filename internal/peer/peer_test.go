package peer

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

const testKey = "08dzv758I5APqJizgw/W6O+FceyHSCbx/L/GZ3TL5TQ="

func i32(v int32) *int32 { return &v }

func iedon() dn42v1.DN42PeerSpec {
	return dn42v1.DN42PeerSpec{
		ASN:        4242422189,
		ListenPort: i32(22189),
		Endpoint:   "[2001:bc8:1640:5bdb:dc00:ff:fe60:c2e3]:60887",
		PublicKey:  testKey,
		Neighbor:   "fe80::2189:177",
		Link:       &dn42v1.LinkValues{Latency: 2, Bandwidth: 24, Crypto: 34},
		KeyRef:     "iedon",
	}
}

func TestFromSpecValid(t *testing.T) {
	p, err := FromSpec("iedon", ptr(iedon()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Interface() != "wg-iedon" || p.Protocol() != "peer_iedon" {
		t.Errorf("names: %s %s", p.Interface(), p.Protocol())
	}
	if p.ListenPort != 22189 || p.ASN != 4242422189 {
		t.Errorf("port/asn: %d %d", p.ListenPort, p.ASN)
	}
	if p.Endpoint.String() != "[2001:bc8:1640:5bdb:dc00:ff:fe60:c2e3]:60887" {
		t.Errorf("endpoint %s", p.Endpoint)
	}
	if p.LocalLinkLocal != DefaultLocalLinkLocal {
		t.Errorf("local %s", p.LocalLinkLocal)
	}
}

func ptr[T any](v T) *T { return &v }

func TestDefaultListenPort(t *testing.T) {
	s := iedon()
	s.ListenPort = nil
	s.ASN = 4242420253
	p, err := FromSpec("moe", &s)
	if err != nil {
		t.Fatal(err)
	}
	if p.ListenPort != 20253 {
		t.Errorf("got %d", p.ListenPort)
	}
	// Non-4242 ASN: no guessing.
	s.ASN = 4201271111
	_, err = FromSpec("neo", &s)
	if err == nil || err.Reason != ReasonListenPortRequired {
		t.Fatalf("want ListenPortRequired, got %v", err)
	}
	s.ListenPort = i32(21111)
	if _, err := FromSpec("neo", &s); err != nil {
		t.Fatal(err)
	}
}

func TestFromSpecInvalid(t *testing.T) {
	cases := map[string]func(*dn42v1.DN42PeerSpec) string{
		"asn":            func(s *dn42v1.DN42PeerSpec) string { s.ASN = 13335; return "" },
		"port low":       func(s *dn42v1.DN42PeerSpec) string { s.ListenPort = i32(1000); return "" },
		"key short":      func(s *dn42v1.DN42PeerSpec) string { s.PublicKey = "AAAA"; return "" },
		"key bad b64":    func(s *dn42v1.DN42PeerSpec) string { s.PublicKey = strings.Repeat("!", 43) + "="; return "" },
		"neighbor ula":   func(s *dn42v1.DN42PeerSpec) string { s.Neighbor = "fd42::1"; return "" },
		"neighbor zone":  func(s *dn42v1.DN42PeerSpec) string { s.Neighbor = "fe80::1%eth0"; return "" },
		"neighbor v4":    func(s *dn42v1.DN42PeerSpec) string { s.Neighbor = "169.254.0.1"; return "" },
		"local ula":      func(s *dn42v1.DN42PeerSpec) string { s.LocalLinkLocal = "fd00::1"; return "" },
		"same address":   func(s *dn42v1.DN42PeerSpec) string { s.LocalLinkLocal = s.Neighbor; return "" },
		"endpoint v6":    func(s *dn42v1.DN42PeerSpec) string { s.Endpoint = "2001:db8::1:51820"; return "" },
		"endpoint port":  func(s *dn42v1.DN42PeerSpec) string { s.Endpoint = "[2001:db8::1]:70000"; return "" },
		"endpoint host":  func(s *dn42v1.DN42PeerSpec) string { s.Endpoint = "bad_host;rm:1"; return "" },
		"endpoint mcast": func(s *dn42v1.DN42PeerSpec) string { s.Endpoint = "[ff02::1]:1"; return "" },
		"latency":        func(s *dn42v1.DN42PeerSpec) string { s.Link.Latency = 10; return "" },
		"bandwidth":      func(s *dn42v1.DN42PeerSpec) string { s.Link.Bandwidth = 29; return "" },
		"crypto":         func(s *dn42v1.DN42PeerSpec) string { s.Link.Crypto = 30; return "" },
		"keyref":         func(s *dn42v1.DN42PeerSpec) string { s.KeyRef = "a/b"; return "" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := iedon()
			mod(&s)
			if _, err := FromSpec("iedon", &s); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{"a", "iedon", "abcdefghijkl", "x1"} {
		if ValidateName(n) != nil {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "1abc", "abcdefghijklm", "Iedon", "ie-don", "ie_don"} {
		if ValidateName(n) == nil {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestEndpointHostname(t *testing.T) {
	ep, err := ParseEndpoint("NL-AMS.dn42.iedon.net:60887")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "nl-ams.dn42.iedon.net" || ep.Port != 60887 {
		t.Errorf("%+v", ep)
	}
	ep, err = ParseEndpoint("192.0.2.1:51820")
	if err != nil || ep.String() != "192.0.2.1:51820" {
		t.Errorf("%v %v", ep, err)
	}
}

func obj(name string, created int, s dn42v1.DN42PeerSpec) dn42v1.DN42Peer {
	return dn42v1.DN42Peer{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(time.Unix(int64(created), 0))},
		Spec:       s,
	}
}

func TestValidateSetConflicts(t *testing.T) {
	a := iedon()
	b := iedon()
	b.Neighbor = "fe80::2"
	b.PublicKey = "xAEAuM4uK5+j5kwRGIW6KYEsJVy0/6Awc4x8mpmKuSw="
	c := iedon()
	c.ListenPort = i32(22190)
	// "zz" is older than "aa", so "aa" loses the port.
	res := ValidateSet([]dn42v1.DN42Peer{obj("aa", 20, b), obj("zz", 10, a), obj("cc", 30, c)})
	got := map[string]string{}
	for _, r := range res {
		if r.Err != nil {
			got[r.Object.Name] = r.Err.Reason
		} else {
			got[r.Object.Name] = "ok"
		}
	}
	want := map[string]string{"zz": "ok", "aa": ReasonPortConflict, "cc": ReasonNeighborConflict}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %s, want %s", k, got[k], v)
		}
	}
	if res[0].Object.Name != "aa" || res[2].Object.Name != "zz" {
		t.Error("results not sorted by name")
	}
}

func TestValidateSetDefaultPortCollision(t *testing.T) {
	// listenPort 22189 set explicitly on one, the other derives 22189 from
	// its ASN: same port, the newer one is invalid with a clear message.
	a := iedon()
	a.ASN = 4242420001 // explicit port 22189
	b := iedon()
	b.ListenPort = nil // derives 22189 from AS4242422189
	b.Neighbor = "fe80::99"
	res := ValidateSet([]dn42v1.DN42Peer{obj("old", 1, a), obj("new", 2, b)})
	for _, r := range res {
		if r.Object.Name == "new" {
			if r.Err == nil || r.Err.Reason != ReasonPortConflict || !strings.Contains(r.Err.Message, "old") {
				t.Fatalf("got %v", r.Err)
			}
		} else if r.Err != nil {
			t.Fatalf("old: %v", r.Err)
		}
	}
}

func TestIsDN42ASN(t *testing.T) {
	for _, a := range []int64{4242420000, 4242429999, 4201271111, 64512, 65534, 76100} {
		if !IsDN42ASN(a) {
			t.Errorf("%d", a)
		}
	}
	for _, a := range []int64{4242419999, 4242430000, 65535, 0, 13335} {
		if IsDN42ASN(a) {
			t.Errorf("%d", a)
		}
	}
}

func TestMTUAndLocalLinkLocal(t *testing.T) {
	s := iedon()
	p, err := FromSpec("iedon", &s)
	if err != nil || p.MTU != DefaultMTU || p.LocalLinkLocal != DefaultLocalLinkLocal {
		t.Fatalf("defaults: %+v %v", p, err)
	}
	// zz assigns fixed link-locals: we are fe80::2, they are fe80::1.
	s.LocalLinkLocal, s.Neighbor, s.MTU = "fe80::2", "fe80::1", i32(1380)
	p, err = FromSpec("zz", &s)
	if err != nil || p.MTU != 1380 || p.LocalLinkLocal.String() != "fe80::2" || p.Neighbor.String() != "fe80::1" {
		t.Fatalf("zz: %+v %v", p, err)
	}
	for _, bad := range []int32{1279, 1501, 0} {
		s.MTU = i32(bad)
		if _, err := FromSpec("zz", &s); err == nil {
			t.Errorf("mtu %d accepted", bad)
		}
	}
}
