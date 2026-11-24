package autopeer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

const (
	ourPub   = "Z+E2LCtW2d1RF/RY7H3jUTK3lTP3KGx8JGWpNbRYMBk="
	theirPub = "08dzv758I5APqJizgw/W6O+FceyHSCbx/L/GZ3TL5TQ="
)

func testConfig(t *testing.T, providers ...ProviderConfig) *Config {
	t.Helper()
	if len(providers) == 0 {
		providers = []ProviderConfig{{Name: "test", ClientID: "c", Issuer: "http://x", Claims: ClaimsConfig{ASN: "asn"}}}
	}
	c := &Config{
		PublicURL: "https://autopeer.example/",
		Router:    RouterConfig{ASN: 4242423818, Name: "oscrx", EndpointHost: "2001:db8::4242", PublicKey: ourPub},
		Providers: providers,
	}
	if err := c.complete(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIdentityFromClaims(t *testing.T) {
	p := &ProviderConfig{Name: "x", Claims: ClaimsConfig{Subject: "sub", ASN: "dn42.asn"}}
	cases := []struct {
		claims map[string]any
		want   []int64
	}{
		{map[string]any{"sub": "u", "dn42": map[string]any{"asn": "AS4242423914"}}, []int64{4242423914}},
		{map[string]any{"sub": "u", "dn42": map[string]any{"asn": float64(4242423914)}}, []int64{4242423914}},
		{map[string]any{"sub": "u", "dn42": map[string]any{"asn": []any{"4242420010", "AS4242420011", "13335"}}}, []int64{4242420010, 4242420011}},
		{map[string]any{"sub": "u", "dn42": map[string]any{"asn": "AS4242420010, AS4242420011"}}, []int64{4242420010, 4242420011}},
	}
	for i, c := range cases {
		id, err := IdentityFromClaims(p, c.claims)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if len(id.ASNs) != len(c.want) {
			t.Errorf("%d: got %v want %v", i, id.ASNs, c.want)
			continue
		}
		for j := range c.want {
			if id.ASNs[j] != c.want[j] {
				t.Errorf("%d: got %v want %v", i, id.ASNs, c.want)
			}
		}
	}
	if _, err := IdentityFromClaims(p, map[string]any{"sub": "u", "mnt": "FOO-MNT"}); err == nil {
		t.Error("identity without ASN accepted")
	}
	if _, err := IdentityFromClaims(p, map[string]any{"dn42": map[string]any{"asn": "4242420001"}}); err == nil {
		t.Error("identity without subject accepted")
	}
	if _, err := IdentityFromClaims(p, map[string]any{"sub": "u", "dn42": map[string]any{"asn": "13335"}}); err == nil {
		t.Error("non-DN42 ASN accepted")
	}
}

func TestIdentityName(t *testing.T) {
	p := &ProviderConfig{Name: "x", Claims: ClaimsConfig{Subject: "sub", Name: "dn42.active_mnt", ASN: "dn42.asn"}}
	id, err := IdentityFromClaims(p, map[string]any{"sub": "e435", "dn42": map[string]any{"asn": 4242423818.0, "active_mnt": "OSCRX-MNT"}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "e435" || id.DisplayName() != "OSCRX-MNT" {
		t.Errorf("subject %q name %q", id.Subject, id.DisplayName())
	}
	if got, want := id.Login(), "`OSCRX-MNT` (x, subject `e435`)"; got != want {
		t.Errorf("login %q, want %q", got, want)
	}
	// No name claim: the subject stands in.
	id, err = IdentityFromClaims(p, map[string]any{"sub": "e435", "dn42": map[string]any{"asn": "4242423818"}})
	if err != nil {
		t.Fatal(err)
	}
	if id.DisplayName() != "e435" || id.Login() != "`e435` (x)" {
		t.Errorf("fallback: name %q login %q", id.DisplayName(), id.Login())
	}
}

func TestCookies(t *testing.T) {
	c, err := NewCookies(make([]byte, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := c.Set(rec, "a", map[string]int{"x": 1}, time.Minute); err != nil {
		t.Fatal(err)
	}
	ck := rec.Result().Cookies()[0]
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: %+v", ck)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	var v map[string]int
	if err := c.Get(req, "a", &v); err != nil || v["x"] != 1 {
		t.Fatalf("%v %v", v, err)
	}
	// Same value under another name: refused.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "b", Value: ck.Value})
	if err := c.Get(req, "b", &v); err == nil {
		t.Error("cookie moved to another name accepted")
	}
	// Tampered.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	bad := []byte(ck.Value)
	bad[len(bad)/2] ^= 1
	req.AddCookie(&http.Cookie{Name: "a", Value: string(bad)})
	if err := c.Get(req, "a", &v); err == nil {
		t.Error("tampered cookie accepted")
	}
	// Expired.
	rec = httptest.NewRecorder()
	_ = c.Set(rec, "a", 1, -time.Second)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "a", Value: rec.Result().Cookies()[0].Value})
	if err := c.Get(req, "a", &v); err == nil {
		t.Error("expired cookie accepted")
	}
	if _, err := NewCookies(make([]byte, 16), true); err == nil {
		t.Error("short key accepted")
	}
}

func existingPeer(name string, asn int64, port int32, neighbor string) dn42v1.DN42Peer {
	p := dn42v1.DN42Peer{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: dn42v1.DN42PeerSpec{ASN: asn, PublicKey: theirPub, Neighbor: neighbor}}
	if port != 0 {
		p.Spec.ListenPort = &port
	}
	return p
}

func TestBuildPeer(t *testing.T) {
	cfg := testConfig(t)
	id := &Identity{Subject: "u", ASNs: []int64{4242420001, 4242420002, 4201270001, 4242423818}}
	req := Request{ASN: 4242420001, Name: "Alpha", PublicKey: theirPub, Endpoint: "[2001:db8::1]:23818", Neighbor: "fe80::1"}

	obj, p, err := BuildPeer(cfg, id, &req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Name != "alpha" || *obj.Spec.ListenPort != 20001 || p.ListenPort != 20001 || obj.Spec.KeyRef != "" {
		t.Errorf("%+v", obj.Spec)
	}

	// Default port taken: highest free port, written explicitly.
	existing := []dn42v1.DN42Peer{existingPeer("other", 4242420009, 20001, "fe80::9"), existingPeer("top", 4242420008, 29999, "fe80::8")}
	obj, _, err = BuildPeer(cfg, id, &req, existing)
	if err != nil || *obj.Spec.ListenPort != 29998 {
		t.Fatalf("port %v err %v", obj, err)
	}
	// Non-4242 ASN gets an explicit port too.
	r2 := req
	r2.ASN = 4201270001
	if obj, _, err := BuildPeer(cfg, id, &r2, nil); err != nil || *obj.Spec.ListenPort != 29999 {
		t.Fatalf("non-4242: %v %v", obj, err)
	}

	bad := []struct {
		field string
		mod   func(*Request)
		ex    []dn42v1.DN42Peer
	}{
		{"asn", func(r *Request) { r.ASN = 4242420099 }, nil},
		{"asn", func(r *Request) { r.ASN = cfg.Router.ASN }, nil},
		{"name", func(r *Request) { r.Name = "1bad" }, nil},
		{"name", func(r *Request) { r.Name = "x\"; }" }, nil},
		{"name", func(r *Request) {}, []dn42v1.DN42Peer{existingPeer("alpha", 4242420005, 0, "fe80::5")}},
		{"publicKey", func(r *Request) { r.PublicKey = "nope" }, nil},
		{"endpoint", func(r *Request) { r.Endpoint = "2001:db8::1:23818" }, nil},
		{"neighbor", func(r *Request) { r.Neighbor = "fd00::1" }, nil},
		{"neighbor", func(r *Request) { r.Neighbor = "fe80::3818" }, nil},
		{"neighbor", func(r *Request) {}, []dn42v1.DN42Peer{existingPeer("old", 4242420001, 22222, "fe80::1")}},
	}
	for i, b := range bad {
		r := req
		b.mod(&r)
		_, _, err := BuildPeer(cfg, id, &r, b.ex)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != b.field {
			t.Errorf("%d: want field %s, got %v", i, b.field, err)
		}
	}
}

func TestRenderPeerSide(t *testing.T) {
	cfg := testConfig(t)
	id := &Identity{ASNs: []int64{4242420001}}
	_, p, err := BuildPeer(cfg, id, &Request{ASN: 4242420001, Name: "alpha", PublicKey: theirPub,
		Endpoint: "[2001:db8::1]:51820", Neighbor: "fe80::1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	side, err := RenderPeerSide(cfg, p, cfg.routerKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ListenPort = 51820", "PublicKey = " + ourPub, "Endpoint = [2001:db8::4242]:20001",
		"ip addr add fe80::1/64 dev %i", "AllowedIPs = fe80::/10, fd00::/8", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(side.WireGuard, want) {
			t.Errorf("wireguard config lacks %q:\n%s", want, side.WireGuard)
		}
	}
	for _, want := range []string{"neighbor fe80::3818 as 4242423818;", `interface "dn42-oscrx";`, "protocol bgp dn42_oscrx"} {
		if !strings.Contains(side.BIRD, want) {
			t.Errorf("bird config lacks %q:\n%s", want, side.BIRD)
		}
	}
	// Without their endpoint: they listen on 2 + last 4 digits of our ASN.
	p.Endpoint = nil
	side, _ = RenderPeerSide(cfg, p, cfg.routerKey())
	if !strings.Contains(side.WireGuard, "ListenPort = 23818") {
		t.Errorf("default port:\n%s", side.WireGuard)
	}
}

func TestPeerYAMLRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	obj, _, err := BuildPeer(cfg, &Identity{ASNs: []int64{4242420001}},
		&Request{ASN: 4242420001, Name: "alpha", PublicKey: theirPub, Neighbor: "fe80::1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PeerYAML(obj)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "namespace") || strings.Contains(string(b), "status") {
		t.Errorf("unexpected fields:\n%s", b)
	}
	back, err := ParsePeerFile(b)
	if err != nil || back.Name != "alpha" || *back.Spec.ListenPort != 20001 {
		t.Fatalf("%v %v\n%s", back, err, b)
	}
	if _, err := ParsePeerFile(append(b, []byte("  bogus: 1\n")...)); err == nil {
		t.Error("unknown field accepted")
	}
	if got := PeerFileName("peers", obj); got != "peers/4242420001-alpha.yaml" {
		t.Error(got)
	}
}

func TestConfigChecks(t *testing.T) {
	c := testConfig(t)
	c.Providers = append(c.Providers, ProviderConfig{Name: "test", ClientID: "c", Issuer: "http://x", Claims: ClaimsConfig{ASN: "a"}})
	if err := c.complete(); err == nil {
		t.Error("duplicate provider accepted")
	}
	c = testConfig(t)
	c.Providers[0].Claims = ClaimsConfig{}
	if err := c.complete(); err == nil {
		t.Error("provider without claims accepted")
	}
	c = testConfig(t)
	c.Providers[0].Issuer = ""
	if err := c.complete(); err == nil {
		t.Error("provider without endpoints accepted")
	}
	c = testConfig(t)
	c.Admin = AdminConfig{Enabled: true, Providers: []string{"nope"}}
	if err := c.complete(); err == nil {
		t.Error("admin.providers with an unknown provider accepted")
	}
}

func TestExampleConfigParses(t *testing.T) {
	b, err := os.ReadFile("../../deploy/autopeer-config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The example has placeholder secrets and key; make them loadable.
	s := strings.ReplaceAll(string(b), "REPLACE_WITH_SHARED_AUTOPEER_PUBLIC_KEY=", ourPub)
	s = strings.ReplaceAll(s, "/secrets/", dir+"/")
	for _, f := range []string{"iedon-client-secret", "hexp-client-secret"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 4 || c.SessionTTL.Duration != time.Hour {
		t.Errorf("%+v", c)
	}
}

func TestClaimNames(t *testing.T) {
	got := strings.Join(claimNames(map[string]any{"sub": "x", "dn42": map[string]any{"asn": 1.0, "active_mnt": "M"}}, ""), ",")
	if got != "dn42.active_mnt,dn42.asn,sub" {
		t.Errorf("got %s", got)
	}
}
