package autopeer

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := &Limiter{PerKey: 2, Total: 3, Now: func() time.Time { return now }}
	for i, want := range []bool{true, true, false} {
		if got := l.Allow("a"); got != want {
			t.Errorf("per-key limit, call %d: %v", i, got)
		}
	}
	if !l.Allow("b") || l.Allow("c") {
		t.Error("total limit")
	}
	now = now.Add(61 * time.Minute)
	if !l.Allow("a") {
		t.Error("window did not slide")
	}
}

func TestBaseFor(t *testing.T) {
	c := testConfig(t)
	c.ExtraPublicURLs = []string{"https://autopeer.oscrx.dn42/"}
	if err := c.complete(); err != nil {
		t.Fatal(err)
	}
	if got := c.BaseFor("AUTOPEER.oscrx.dn42"); got != "https://autopeer.oscrx.dn42" {
		t.Error(got)
	}
	if got := c.BaseFor("evil.example"); got != "https://autopeer.example" {
		t.Error(got)
	}
	c.ExtraPublicURLs = []string{"https://x.example/path"}
	if err := c.complete(); err == nil {
		t.Error("URL with a path accepted")
	}
}

func TestLoginRedirectPerHost(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	a := newAppCfg(t, func(c *Config) { c.ExtraPublicURLs = []string{"https://autopeer.oscrx.dn42"} },
		ProviderConfig{Name: "x", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	stop := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for host, want := range map[string]string{
		"autopeer.oscrx.dn42": "https://autopeer.oscrx.dn42/auth/x/callback",
		"evil.example":        a.srv.URL + "/auth/x/callback",
	} {
		req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/login/x", nil)
		req.Host = host
		resp, err := stop.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		if got := u.Query().Get("redirect_uri"); got != want {
			t.Errorf("host %s: redirect_uri %q, want %q", host, got, want)
		}
	}
}

func loggedIn(t *testing.T, mut func(*Config)) *app {
	idp := newFakeIdP(t, map[string]any{"asn": []any{"4242420010", "4242420011"}})
	a := newAppCfg(t, mut, ProviderConfig{Name: "x", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	if code, _ := a.get("/login/x"); code != 200 {
		t.Fatal("login failed")
	}
	return a
}

func peerForm(a *app, name, neighbor string) url.Values {
	return url.Values{"csrf": {a.csrf()}, "asn": {"4242420010"}, "name": {name}, "publicKey": {theirPub}, "neighbor": {neighbor}}
}

func TestPendingPRBlocksDuplicates(t *testing.T) {
	a := loggedIn(t, nil)
	if code, _ := a.post("/peer", peerForm(a, "kio", "fe80::10")); code != 200 {
		t.Fatal("first submit")
	}
	// Same name while the first PR is open.
	if code, body := a.post("/peer", peerForm(a, "kio", "fe80::11")); code != 422 || !strings.Contains(body, "already taken") {
		t.Errorf("same name: %d", code)
	}
	// Same ASN + neighbor under another name.
	if code, body := a.post("/peer", peerForm(a, "kio2", "fe80::10")); code != 422 || !strings.Contains(body, "neighbor fe80::10") {
		t.Errorf("same neighbor: %d\n%s", code, body)
	}
	// The second, different request gets the next port, not the pending one.
	if code, _ := a.post("/peer", peerForm(a, "kio3", "fe80::12")); code != 200 {
		t.Fatal("third submit")
	}
	obj, _ := ParsePeerFile(a.repo.PRs[1].Content)
	if *obj.Spec.ListenPort == 20010 {
		t.Error("port of the pending PR reused")
	}
	// The home page shows both as pending.
	_, body := a.get("/")
	if strings.Count(body, ">PR open<") != 2 {
		t.Errorf("pending not shown:\n%s", body)
	}
}

func TestRateLimit(t *testing.T) {
	a := loggedIn(t, func(c *Config) { c.Limits.PerLoginPerHour = 1 })
	if code, _ := a.post("/peer", peerForm(a, "kio", "fe80::10")); code != 200 {
		t.Fatal("first submit")
	}
	if code, _ := a.post("/peer", peerForm(a, "kio2", "fe80::11")); code != http.StatusTooManyRequests {
		t.Errorf("second submit: %d", code)
	}
	if len(a.repo.PRs) != 1 {
		t.Error("PR opened over the limit")
	}
}

func TestRemovePeer(t *testing.T) {
	a := loggedIn(t, nil)
	mine := existingPeer("mine", 4242420010, 20010, "fe80::1")
	hand := existingPeer("hand", 4242420011, 20011, "fe80::2")
	hand.Spec.KeyRef = "hand"
	other := existingPeer("other", 4242420099, 20099, "fe80::3")
	for _, p := range []*dn42v1.DN42Peer{&mine, &hand, &other} {
		b, _ := PeerYAML(p)
		a.repo.Files[PeerFileName("peers", p)] = b
	}
	_, body := a.get("/")
	// Peers with their own key (keyRef) are removable like any other.
	if !strings.Contains(body, `href="/peer/remove?name=mine"`) || !strings.Contains(body, `href="/peer/remove?name=hand"`) {
		t.Errorf("remove links:\n%s", body)
	}
	// Remove asks first; the confirmation page itself changes nothing.
	if code, body := a.get("/peer/remove?name=mine"); code != 200 || !strings.Contains(body, "Yes, remove mine") ||
		!strings.Contains(body, `action="/peer/remove"`) || len(a.repo.PRs) != 0 {
		t.Errorf("confirmation: %d PRs %d\n%s", code, len(a.repo.PRs), body)
	}
	if code, _ := a.get("/peer/remove?name=other"); code != http.StatusNotFound {
		t.Errorf("confirmation for someone else's peer: %d", code)
	}
	csrf := a.csrf()
	rm := func(name string) int {
		code, _ := a.post("/peer/remove", url.Values{"csrf": {csrf}, "name": {name}})
		return code
	}
	if code := rm("mine"); code != 200 {
		t.Fatalf("remove mine: %d", code)
	}
	pr := a.repo.PRs[0]
	if !pr.Delete || pr.Path != "peers/4242420010-mine.yaml" || !strings.HasPrefix(pr.Branch, "autopeer/remove-") {
		t.Errorf("PR: %+v", pr)
	}
	if code := rm("mine"); code != http.StatusConflict {
		t.Errorf("second removal: %d", code)
	}
	if code := rm("hand"); code != 200 {
		t.Errorf("keyRef peer: %d", code)
	}
	if code := rm("other"); code != http.StatusNotFound {
		t.Errorf("someone else's: %d", code)
	}
	if code := rm("nope"); code != http.StatusNotFound {
		t.Errorf("missing: %d", code)
	}
	if code, _ := a.post("/peer/remove", url.Values{"name": {"mine"}}); code != http.StatusForbidden {
		t.Errorf("no csrf: %d", code)
	}
	if len(a.repo.PRs) != 2 {
		t.Errorf("PRs: %d", len(a.repo.PRs))
	}
}

func TestEditPeer(t *testing.T) {
	a := loggedIn(t, nil)
	mine := existingPeer("mine", 4242420010, 20010, "fe80::1")
	mine.Spec.Link = &dn42v1.LinkValues{Latency: 3, Bandwidth: 25, Crypto: 34}
	neighbor := existingPeer("nb", 4242420010, 20011, "fe80::2")
	hand := existingPeer("hand", 4242420011, 20012, "fe80::3")
	hand.Spec.KeyRef = "hand"
	for _, p := range []*dn42v1.DN42Peer{&mine, &neighbor, &hand} {
		b, _ := PeerYAML(p)
		a.repo.Files[PeerFileName("peers", p)] = b
	}
	if code, body := a.get("/peer/edit?name=mine"); code != 200 || !strings.Contains(body, `value="fe80::1"`) {
		t.Fatalf("edit form: %d\n%s", code, body)
	}
	if code, _ := a.get("/peer/edit?name=hand"); code != 200 {
		t.Errorf("keyRef peer edit form: %d", code)
	}
	csrf := a.csrf()
	edit := func(pub, ep, nb string) (int, string) {
		return a.post("/peer/edit", url.Values{"csrf": {csrf}, "name": {"mine"}, "publicKey": {pub}, "endpoint": {ep}, "neighbor": {nb}})
	}
	if code, body := edit(theirPub, "", "fe80::1"); code != 422 || !strings.Contains(body, "nothing changed") {
		t.Errorf("no-op edit: %d", code)
	}
	if code, body := edit(theirPub, "", "fe80::2"); code != 422 || !strings.Contains(body, "neighbor fe80::2") {
		t.Errorf("neighbor clash: %d", code)
	}
	if code, _ := edit("bad", "", "fe80::1"); code != 422 {
		t.Errorf("bad key: %d", code)
	}
	newKey := "xAEAuM4uK5+j5kwRGIW6KYEsJVy0/6Awc4x8mpmKuSw="
	if code, body := edit(newKey, "[2001:db8::7]:51820", "fe80::1"); code != 200 || !strings.Contains(body, "ListenPort = 51820") {
		t.Fatalf("edit: %d\n%s", code, body)
	}
	pr := a.repo.PRs[0]
	obj, err := ParsePeerFile(pr.Content)
	if err != nil || pr.Delete || pr.Path != "peers/4242420010-mine.yaml" || !strings.HasPrefix(pr.Branch, "autopeer/edit-") {
		t.Fatalf("PR %+v %v", pr, err)
	}
	// Peer-controlled fields changed; name, ASN, port and link values kept.
	if obj.Spec.PublicKey != newKey || obj.Spec.Endpoint != "[2001:db8::7]:51820" || *obj.Spec.ListenPort != 20010 ||
		obj.Spec.Link == nil || obj.Spec.Link.Latency != 3 || obj.Name != "mine" || obj.Spec.KeyRef != "" {
		t.Errorf("updated spec: %+v", obj.Spec)
	}
	// While that PR is open, no second edit or removal.
	if code, _ := edit(theirPub, "", "fe80::9"); code != http.StatusConflict {
		t.Errorf("edit while pending: %d", code)
	}
}

func TestHostIssuers(t *testing.T) {
	clear := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	dn42 := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	a := newAppCfg(t, func(c *Config) {
		c.ExtraPublicURLs = []string{"https://autopeer.oscrx.dn42"}
		c.Providers[0].HostIssuers = map[string]string{"autopeer.oscrx.dn42": dn42.srv.URL}
	}, ProviderConfig{Name: "x", Issuer: clear.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	stop := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for host, want := range map[string]string{
		"autopeer.oscrx.dn42": dn42.srv.URL,
		"evil.example":        clear.srv.URL, // unknown host: the primary URL and issuer
	} {
		req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/login/x", nil)
		req.Host = host
		resp, err := stop.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, want+"/") {
			t.Errorf("host %s: sent to %s, want %s", host, loc, want)
		}
	}
	// Full login on the primary host still works with the primary issuer.
	if _, body := a.get("/login/x"); !strings.Contains(body, "AS4242420010") {
		t.Errorf("login:\n%s", body)
	}
	// A flow can only use a configured issuer.
	p := NewProvider(&ProviderConfig{Name: "x", Issuer: clear.srv.URL, ClientID: "cid"})
	if _, err := p.AuthCodeURL(t.Context(), NewFlow("x", "https://app/cb", dn42.srv.URL)); err == nil {
		t.Error("unconfigured issuer accepted")
	}

	c := testConfig(t)
	c.Providers[0].HostIssuers = map[string]string{"other.example": "https://oauth.dn42"}
	if err := c.complete(); err == nil {
		t.Error("hostIssuers for a host we don't serve accepted")
	}
	c = testConfig(t)
	c.ExtraPublicURLs = []string{"https://autopeer.oscrx.dn42"}
	c.Providers[0].HostIssuers = map[string]string{"autopeer.oscrx.dn42": "http://oauth.dn42"}
	if err := c.complete(); err == nil {
		t.Error("non-https host issuer accepted")
	}
	c.Providers[0].HostIssuers = map[string]string{"autopeer.oscrx.dn42": "https://oauth.dn42"}
	if err := c.complete(); err != nil {
		t.Errorf("valid hostIssuers: %v", err)
	}
}

func TestLoginButtons(t *testing.T) {
	icon := "data:image/png;base64,iVBORw0KGgo="
	a := newApp(t,
		ProviderConfig{Name: "a", DisplayName: "Alpha", Icon: icon, Issuer: "http://unused", ClientID: "c", Claims: ClaimsConfig{ASN: "asn"}},
		ProviderConfig{Name: "b", DisplayName: "beta", Issuer: "http://unused", ClientID: "c", Claims: ClaimsConfig{ASN: "asn"}})
	_, body := a.get("/")
	for _, want := range []string{`<img src="` + icon + `"`, "Log in with Alpha", `<span class="initial">B</span>Log in with beta`} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q in:\n%s", want, body)
		}
	}
	c := testConfig(t)
	c.Providers[0].Icon = "https://provider.example/logo.png"
	if err := c.complete(); err == nil {
		t.Error("non-data icon accepted")
	}
}

func TestSuggest(t *testing.T) {
	cfg := testConfig(t)
	for _, c := range []struct {
		id         Identity
		name, addr string
	}{
		{Identity{Subject: "OSCRX-MNT", ASNs: []int64{4242421234}}, "oscrx", "fe80::1234"},
		{Identity{Subject: "h", Name: "Some-Net_42-MNT", ASNs: []int64{4242423818, 4242420042}}, "somenet42", "fe80::42"},
		{Identity{Subject: "e4358a", Name: "9LIVES-MNT", ASNs: []int64{4201270001}}, "", "fe80::1"},
		{Identity{Subject: "OSCRX-MNT", ASNs: []int64{4242421234}, Admin: true}, "", ""},
	} {
		if n, a := Suggest(cfg, &c.id); n != c.name || a != c.addr {
			t.Errorf("%+v: %q %q, want %q %q", c.id, n, a, c.name, c.addr)
		}
	}
}

func TestPeerDetailsAndMTU(t *testing.T) {
	a := loggedIn(t, nil)
	// The new-peering form suggests the link-local from the first ASN.
	if _, body := a.get("/peer/new"); !strings.Contains(body, `value="fe80::10"`) {
		t.Errorf("no suggested link-local:\n%s", body)
	}
	// IPv4 endpoints are refused; an MTU is written to the file.
	f := peerForm(a, "mine", "fe80::1")
	f.Set("endpoint", "192.0.2.1:23818")
	if code, body := a.post("/peer", f); code != 422 || !strings.Contains(body, "IPv6 only") {
		t.Errorf("IPv4 endpoint: %d", code)
	}
	f.Set("endpoint", "")
	f.Set("mtu", "1200")
	if code, _ := a.post("/peer", f); code != 422 {
		t.Errorf("MTU out of range: %d", code)
	}
	f.Set("mtu", "1380")
	if code, body := a.post("/peer", f); code != 200 || !strings.Contains(body, "MTU = 1380") {
		t.Fatalf("submit: %d\n%s", code, body)
	}
	obj, _ := ParsePeerFile(a.repo.PRs[0].Content)
	if obj.Spec.MTU == nil || *obj.Spec.MTU != 1380 {
		t.Errorf("mtu: %v", obj.Spec.MTU)
	}

	// Once live, the details page shows the config with our key from the
	// status (here a keyRef peer's own key, not the shared one).
	own, _ := wgtypes.GeneratePrivateKey()
	hand := existingPeer("hand", 4242420011, 20011, "fe80::11")
	hand.Spec.KeyRef = "hand"
	b, _ := PeerYAML(&hand)
	a.repo.Files[PeerFileName("peers", &hand)] = b
	live := hand
	live.Status.PublicKey = own.PublicKey().String()
	live.Status.BGPState = "Established"
	a.live = []dn42v1.DN42Peer{live}
	_, body := a.get("/peer/edit?name=hand")
	body = html.UnescapeString(body) // keys may contain '+' (&#43;)
	for _, want := range []string{"PublicKey = " + own.PublicKey().String(), "Established", "fe80::11", "MTU = 1420"} {
		if !strings.Contains(body, want) {
			t.Errorf("details page has no %q:\n%s", want, body)
		}
	}
}

func TestLookingGlassLinks(t *testing.T) {
	a := loggedIn(t, func(c *Config) {
		c.ExtraPublicURLs = []string{"https://autopeer.oscrx.dn42"}
		c.LookingGlass = LookingGlassConfig{URL: "https://lg.example.net", Server: "nl-hou01",
			HostURLs: map[string]string{"autopeer.oscrx.dn42": "https://lg.oscrx.dn42"}}
	})
	p := existingPeer("mine", 4242420010, 20010, "fe80::1")
	b, _ := PeerYAML(&p)
	a.repo.Files[PeerFileName("peers", &p)] = b
	live := p
	live.Status.BGPState = "Established"
	a.live = []dn42v1.DN42Peer{live}
	if _, body := a.get("/"); !strings.Contains(body, `href="https://lg.example.net/detail/nl-hou01/peer_mine"`) {
		t.Errorf("home has no session link:\n%s", body)
	}
	_, body := a.get("/peer/edit?name=mine")
	for _, want := range []string{"/detail/nl-hou01/peer_mine", "/route_from_protocol/nl-hou01/peer_mine", "/whois/AS4242420010"} {
		if !strings.Contains(body, `href="https://lg.example.net`+want+`"`) {
			t.Errorf("details page has no %s link", want)
		}
	}
	// The .dn42 host links to the .dn42 looking glass.
	req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/peer/edit?name=mine", nil)
	req.Host = "autopeer.oscrx.dn42"
	for _, c := range a.c.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := a.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	bb, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(bb), `href="https://lg.oscrx.dn42/detail/nl-hou01/peer_mine"`) {
		t.Errorf(".dn42 host doesn't link the .dn42 looking glass:\n%s", bb)
	}

	c := testConfig(t)
	c.LookingGlass = LookingGlassConfig{URL: "https://lg.example.net"}
	if err := c.complete(); err == nil {
		t.Error("looking glass without server accepted")
	}
	c = testConfig(t)
	c.LookingGlass = LookingGlassConfig{URL: "http://lg.example.net", Server: "x"}
	if err := c.complete(); err == nil {
		t.Error("non-https looking glass accepted")
	}
}

func TestDiscoveryFailureRemembered(t *testing.T) {
	var calls atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	p := NewProvider(&ProviderConfig{Name: "x", Issuer: down.URL, ClientID: "c"})
	for range 3 {
		if _, err := p.AuthCodeURL(t.Context(), NewFlow("x", "https://app/cb", down.URL)); err == nil {
			t.Fatal("discovery of a provider that is down succeeded")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("asked the provider %d times, want 1 within the retry window", n)
	}
}

func TestTransitShown(t *testing.T) {
	a := loggedIn(t, nil)
	var live []dn42v1.DN42Peer
	f, tr := false, true
	for _, c := range []struct {
		name, nb string
		asn      int64
		port     int32
		status   *dn42v1.TransitStatus
	}{
		{"bad", "fe80::1", 4242420010, 20010, &dn42v1.TransitStatus{Healthy: &f, LastResult: dn42v1.TransitBroken, Message: "dns:[fd42:d42:d42:53::1]:53: no reply via the peer"}},
		{"good", "fe80::2", 4242420010, 20011, &dn42v1.TransitStatus{Healthy: &tr, LastResult: dn42v1.TransitHealthy}},
		{"new", "fe80::3", 4242420011, 20012, &dn42v1.TransitStatus{LastResult: dn42v1.TransitBroken}},
		{"none", "fe80::4", 4242420011, 20013, nil},
	} {
		p := existingPeer(c.name, c.asn, c.port, c.nb)
		b, _ := PeerYAML(&p)
		a.repo.Files[PeerFileName("peers", &p)] = b
		p.Status.BGPState = "Established"
		p.Status.Transit = c.status
		live = append(live, p)
	}
	a.live = live
	_, body := a.get("/")
	for _, want := range []string{
		`<span class="pill bad" title="dns:[fd42:d42:d42:53::1]:53: no reply via the peer">broken</span>`,
		`<span class="pill ok" title="">ok</span>`,
		`<span class="pill " title="">checking</span>`,
	} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("home has no %s:\n%s", want, body)
		}
	}
	_, body = a.get("/peer/edit?name=bad")
	if !strings.Contains(body, "transit broken") || !strings.Contains(body, "stateful firewall") {
		t.Errorf("details page doesn't explain the broken transit:\n%s", body)
	}
	if _, body := a.get("/peer/edit?name=good"); strings.Contains(body, "stateful firewall") || !strings.Contains(body, "transit ok") {
		t.Errorf("details page of a healthy peer:\n%s", body)
	}
}
