package autopeer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// fakeIdP is a minimal OIDC/OAuth provider that enforces PKCE S256 and
// signs ID tokens.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // extra claims for the ID token and userinfo
	mu     sync.Mutex
	codes  map[string]authReq
	// tokenCalls counts token exchanges.
	tokenCalls int
}

type authReq struct {
	challenge, nonce, redirect, clientID string
}

func newFakeIdP(t *testing.T, claims map[string]any) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, claims: claims, codes: map[string]authReq{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		u := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
			"jwks_uri": u + "/jwks", "userinfo_endpoint": u + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE S256 required", http.StatusBadRequest)
			return
		}
		code := randomString(8)
		f.mu.Lock()
		f.codes[code] = authReq{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri"), q.Get("client_id")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.tokenCalls++
		ar, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ar.challenge || r.PostForm.Get("redirect_uri") != ar.redirect {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		idc := map[string]any{"iss": f.srv.URL, "aud": ar.clientID, "sub": "user-1", "nonce": ar.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range f.claims {
			idc[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "id_token": f.sign(idc)})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ui := map[string]any{"sub": "user-1"}
		for k, v := range f.claims {
			ui[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ui)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		f.t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := signer.Sign(b)
	if err != nil {
		f.t.Fatal(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

type app struct {
	t    *testing.T
	srv  *httptest.Server
	c    *http.Client
	repo *FakeRepo
}

func newApp(t *testing.T, providers ...ProviderConfig) *app {
	return newAppCfg(t, nil, providers...)
}

func newAppCfg(t *testing.T, mut func(*Config), providers ...ProviderConfig) *app {
	a := &app{t: t, repo: &FakeRepo{Files: map[string][]byte{}}}
	var h http.Handler
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(a.srv.Close)
	cfg := testConfig(t, providers...)
	cfg.PublicURL = a.srv.URL
	if mut != nil {
		mut(cfg)
	}
	cookies, _ := NewCookies(make([]byte, 32), false)
	h = NewServer(cfg, testRegistry(t), a.repo, nil, cookies).Handler()
	jar, _ := cookiejar.New(nil)
	a.c = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	return a
}

func (a *app) get(path string) (int, string) {
	a.t.Helper()
	resp, err := a.c.Get(a.srv.URL + path)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (a *app) post(path string, form url.Values) (int, string) {
	a.t.Helper()
	resp, err := a.c.PostForm(a.srv.URL+path, form)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (a *app) csrf() string {
	_, body := a.get("/peer/new")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		a.t.Fatalf("no csrf in form:\n%s", body)
	}
	return m[1]
}

func TestOIDCLoginAndSubmit(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"dn42": map[string]any{"asn": "AS4242420010"}, "mnt": "FOO-MNT"})
	a := newApp(t, ProviderConfig{Name: "kioubit", DisplayName: "Kioubit", Issuer: idp.srv.URL, ClientID: "cid",
		Scopes: []string{"openid"}, Claims: ClaimsConfig{ASN: "dn42.asn", Mntner: "mnt"}})

	code, body := a.get("/")
	if code != 200 || !strings.Contains(body, `href="/login/kioubit"`) {
		t.Fatalf("login page: %d\n%s", code, body)
	}
	code, body = a.get("/login/kioubit") // follows the IdP redirect back to the callback and home
	if code != 200 || !strings.Contains(body, "AS4242420001, AS4242420002, AS4242420010") {
		t.Fatalf("after login: %d\n%s", code, body)
	}

	form := url.Values{"csrf": {a.csrf()}, "asn": {"4242420010"}, "name": {"kio"}, "publicKey": {theirPub},
		"endpoint": {"[2001:db8::10]:23818"}, "neighbor": {"fe80::10"}}
	code, body = a.post("/peer", form)
	if code != 200 || !strings.Contains(body, "https://github.com/example/peers/pull/1") {
		t.Fatalf("submit: %d\n%s", code, body)
	}
	if !strings.Contains(body, "Endpoint = [2001:db8::4242]:20010") {
		t.Errorf("peer side config missing:\n%s", body)
	}
	if len(a.repo.PRs) != 1 {
		t.Fatalf("PRs: %v", a.repo.PRs)
	}
	pr := a.repo.PRs[0]
	if pr.Path != "peers/4242420010-kio.yaml" || !strings.HasPrefix(pr.Branch, "autopeer/4242420010-kio-") ||
		!strings.Contains(pr.Body, "`user-1` (kioubit)") {
		t.Errorf("PR: %+v", pr)
	}
	obj, err := ParsePeerFile(pr.Content)
	if err != nil || obj.Spec.ASN != 4242420010 || *obj.Spec.ListenPort != 20010 {
		t.Errorf("PR file: %v %v\n%s", obj, err, pr.Content)
	}

	// An ASN the login doesn't cover.
	form.Set("asn", "4242420099")
	form.Set("name", "other")
	if code, body := a.post("/peer", form); code != http.StatusUnprocessableEntity || !strings.Contains(body, "may not manage") {
		t.Errorf("foreign ASN: %d", code)
	}
	// Missing CSRF.
	form.Del("csrf")
	if code, _ := a.post("/peer", form); code != http.StatusForbidden {
		t.Errorf("no csrf: %d", code)
	}
	if len(a.repo.PRs) != 1 {
		t.Error("PR opened for a refused request")
	}
}

func TestOIDCRejects(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	a := newApp(t, ProviderConfig{Name: "x", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})

	// Callback without a login flow (no state cookie).
	if code, _ := a.get("/auth/x/callback?code=abc&state=def"); code != http.StatusBadRequest {
		t.Errorf("callback without flow: %d", code)
	}
	// State mismatch: start a flow, then hit the callback with a forged state.
	stop := &http.Client{Jar: a.c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := stop.Get(a.srv.URL + "/login/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	if authURL.Query().Get("code_challenge_method") != "S256" || authURL.Query().Get("nonce") == "" {
		t.Errorf("auth URL lacks PKCE or nonce: %s", authURL)
	}
	if code, _ := a.get("/auth/x/callback?code=abc&state=forged"); code != http.StatusBadRequest {
		t.Errorf("forged state: %d", code)
	}
	// Replaying a callback fails: the flow cookie is single-use.
	resp, _ = stop.Get(a.srv.URL + "/login/x")
	_ = resp.Body.Close()
	resp, _ = stop.Get(resp.Header.Get("Location")) // IdP -> redirect to callback with code
	_ = resp.Body.Close()
	cb := resp.Header.Get("Location")
	if code, _ := a.get(strings.TrimPrefix(cb, a.srv.URL)); code != 200 {
		t.Fatalf("first redemption: %d", code)
	}
	if code, _ := a.get(strings.TrimPrefix(cb, a.srv.URL)); code == 200 {
		t.Error("callback replay accepted")
	}

	// A provider that returns no DN42 ASN.
	idp2 := newFakeIdP(t, map[string]any{"asn": "13335"})
	b := newApp(t, ProviderConfig{Name: "x", Issuer: idp2.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	if code, body := b.get("/login/x"); code != http.StatusForbidden || !strings.Contains(body, "did not show any DN42 ASN") {
		t.Errorf("no ASN: %d", code)
	}
}

func TestPlainOAuthUserinfo(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"mntner": "BAR-MNT"})
	u := idp.srv.URL
	a := newApp(t, ProviderConfig{Name: "auth42", AuthURL: u + "/authorize", TokenURL: u + "/token", UserinfoURL: u + "/userinfo",
		ClientID: "cid", Claims: ClaimsConfig{Mntner: "mntner"}})
	code, body := a.get("/login/auth42")
	if code != 200 || !strings.Contains(body, "AS4242420002, AS4242420003") {
		t.Fatalf("oauth login: %d\n%s", code, body)
	}
}

func TestHomeShowsOwnPeersOnly(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	a := newApp(t, ProviderConfig{Name: "x", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	mine, _ := PeerYAML(func() *dn42v1.DN42Peer { p := existingPeer("mine", 4242420010, 20010, "fe80::1"); return &p }())
	theirs, _ := PeerYAML(func() *dn42v1.DN42Peer { p := existingPeer("theirs", 4242420011, 20011, "fe80::2"); return &p }())
	a.repo.Files["peers/4242420010-mine.yaml"] = mine
	a.repo.Files["peers/4242420011-theirs.yaml"] = theirs
	_, body := a.get("/login/x")
	if !strings.Contains(body, "<td>mine</td>") || strings.Contains(body, "theirs") {
		t.Errorf("home:\n%s", body)
	}
}

// codeFor runs the authorize step for a flow and returns the code.
func codeFor(t *testing.T, p *Provider, f *Flow) string {
	t.Helper()
	u, err := p.AuthCodeURL(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("code")
}

func TestPKCEAndNonceEnforced(t *testing.T) {
	idp := newFakeIdP(t, map[string]any{"asn": "4242420010"})
	p := NewProvider(&ProviderConfig{Name: "x", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})

	f := NewFlow("x", "https://app/cb")
	code := codeFor(t, p, f)
	wrong := *f
	wrong.Verifier = NewFlow("x", "https://app/cb").Verifier
	if _, err := p.Claims(t.Context(), &wrong, code); err == nil {
		t.Error("code redeemed with the wrong PKCE verifier")
	}

	f = NewFlow("x", "https://app/cb")
	code = codeFor(t, p, f)
	badNonce := *f
	badNonce.Nonce = "other"
	if _, err := p.Claims(t.Context(), &badNonce, code); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("nonce mismatch accepted: %v", err)
	}

	f = NewFlow("x", "https://app/cb")
	claims, err := p.Claims(t.Context(), f, codeFor(t, p, f))
	if err != nil || claims["sub"] != "user-1" || claims["asn"] != "4242420010" {
		t.Errorf("good flow: %v %v", claims, err)
	}
}

func TestAdmin(t *testing.T) {
	own := map[string]any{"asn": "4242423818"}
	prov := func(issuer string) ProviderConfig {
		return ProviderConfig{Name: "x", Issuer: issuer, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}}
	}
	seed := func(a *app) {
		p := existingPeer("theirs", 4242420011, 20011, "fe80::2")
		b, _ := PeerYAML(&p)
		a.repo.Files["peers/4242420011-theirs.yaml"] = b
	}

	// Disabled (the default): our own ASN is just a login with nothing to manage.
	idp := newFakeIdP(t, own)
	a := newApp(t, prov(idp.srv.URL))
	seed(a)
	if _, body := a.get("/login/x"); strings.Contains(body, "admin") || strings.Contains(body, "theirs") {
		t.Errorf("admin while disabled:\n%s", body)
	}

	// Only listed providers grant admin.
	idp = newFakeIdP(t, own)
	a = newAppCfg(t, func(c *Config) { c.Admin = AdminConfig{Enabled: true, Providers: []string{"y"}} },
		prov(idp.srv.URL), ProviderConfig{Name: "y", Issuer: idp.srv.URL, ClientID: "cid", Claims: ClaimsConfig{ASN: "asn"}})
	seed(a)
	if _, body := a.get("/login/x"); strings.Contains(body, "<strong>admin</strong>") {
		t.Errorf("admin through an unlisted provider:\n%s", body)
	}

	// Enabled: every peering is listed, editable, and any DN42 ASN can be added.
	idp = newFakeIdP(t, own)
	a = newAppCfg(t, func(c *Config) { c.Admin.Enabled = true }, prov(idp.srv.URL))
	seed(a)
	_, body := a.get("/login/x")
	if !strings.Contains(body, "<strong>admin</strong>") || !strings.Contains(body, "<td>theirs</td>") ||
		!strings.Contains(body, `href="/peer/edit?name=theirs"`) {
		t.Fatalf("admin home:\n%s", body)
	}
	if _, body := a.get("/peer/new"); !strings.Contains(body, `<input id="asn" name="asn"`) {
		t.Errorf("admin form has no free ASN field:\n%s", body)
	}
	form := url.Values{"csrf": {a.csrf()}, "asn": {"4242420099"}, "name": {"newbie"}, "publicKey": {theirPub},
		"neighbor": {"fe80::99"}}
	if code, body := a.post("/peer", form); code != 200 {
		t.Fatalf("admin add: %d\n%s", code, body)
	}
	if len(a.repo.PRs) != 1 || !strings.Contains(a.repo.PRs[0].Body, "(x, admin)") {
		t.Errorf("PR: %+v", a.repo.PRs)
	}
	// Still no peering with ourselves, nor with non-DN42 ASNs.
	for _, asn := range []string{"4242423818", "13335"} {
		form.Set("asn", asn)
		form.Set("name", "n"+asn[len(asn)-3:])
		if code, _ := a.post("/peer", form); code != http.StatusUnprocessableEntity {
			t.Errorf("admin add AS%s: %d", asn, code)
		}
	}
	// And admins remove other ASNs' peerings.
	rm := url.Values{"csrf": {a.csrf()}, "name": {"theirs"}}
	if code, body := a.post("/peer/remove", rm); code != 200 {
		t.Errorf("admin remove: %d\n%s", code, body)
	}
}
