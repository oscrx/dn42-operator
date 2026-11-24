package autopeer

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
	if !strings.Contains(body, `name="name" value="mine"`) || !strings.Contains(body, `name="name" value="hand"`) {
		t.Errorf("remove buttons:\n%s", body)
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
