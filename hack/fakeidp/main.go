// Command fakeidp is a tiny OpenID Connect provider for trying autopeer
// locally (make run-local): its login page lets you pick the ASNs and the
// mntner you "are", and it answers like the DN42 providers do (a dn42 claim
// with asn and active_mnt). Authorization Code with PKCE S256 only. Never
// expose it: it logs anyone in as anything.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type authReq struct {
	challenge, nonce, redirect, clientID string
	asns                                 []int64
	mntner                               string
}

type idp struct {
	issuer string
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]authReq
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Fake DN42 login</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin-top:1rem;font-weight:600}input{width:100%;padding:.4rem;font:inherit;box-sizing:border-box}
button{margin-top:1.2rem;padding:.5rem 1rem;font:inherit}small{color:#666}</style></head><body>
<h1>Fake DN42 login</h1>
<p><small>Local testing only: you are whoever you say you are.</small></p>
<form method="post" action="/authorize">
{{range $k, $v := .Params}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="asns">ASNs (comma-separated)</label><input id="asns" name="asns" value="4242420042">
<small>Include 4242423818 (the router's own ASN) to log in as admin.</small>
<label for="mntner">Maintainer</label><input id="mntner" name="mntner" value="EXAMPLE-MNT">
<button>Log in</button>
</form></body></html>`))

func main() {
	listen := flag.String("listen", "127.0.0.1:8098", "listen address")
	issuer := flag.String("issuer", "http://localhost:8098", "issuer URL (how autopeer reaches this)")
	flag.Parse()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	p := &idp{issuer: strings.TrimRight(*issuer, "/"), key: key, codes: map[string]authReq{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.form)
	mux.HandleFunc("POST /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	log.Printf("fake DN42 OIDC provider at %s (listening on %s)", p.issuer, *listen)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func (p *idp) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": p.issuer, "authorization_endpoint": p.issuer + "/authorize",
		"token_endpoint": p.issuer + "/token", "jwks_uri": p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "dn42"},
	})
}

func (p *idp) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: "fake", Algorithm: "RS256", Use: "sig"}}})
}

// form shows the login page, carrying the authorization request along.
func (p *idp) form(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "Authorization Code with PKCE S256 required", http.StatusBadRequest)
		return
	}
	params := map[string]string{}
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge"} {
		params[k] = q.Get(k)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, map[string]any{"Params": params})
}

func (p *idp) authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f := r.PostForm
	var asns []int64
	for _, s := range strings.Split(f.Get("asns"), ",") {
		s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			asns = append(asns, n)
		}
	}
	redirect, err := url.Parse(f.Get("redirect_uri"))
	if err != nil || len(asns) == 0 {
		http.Error(w, "need a redirect_uri and at least one ASN", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = authReq{f.Get("code_challenge"), f.Get("nonce"), f.Get("redirect_uri"), f.Get("client_id"),
		asns, strings.ToUpper(strings.TrimSpace(f.Get("mntner")))}
	p.mu.Unlock()
	q := redirect.Query()
	q.Set("code", code)
	q.Set("state", f.Get("state"))
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	ar, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ar.challenge || r.PostForm.Get("redirect_uri") != ar.redirect {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	sub := sha256.Sum256([]byte(ar.mntner))
	claims := map[string]any{
		"iss": p.issuer, "aud": ar.clientID, "nonce": ar.nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"sub":  base64.RawURLEncoding.EncodeToString(sub[:]), // opaque, like OAuth.dn42's
		"dn42": map[string]any{"asn": ar.asns, "active_mnt": ar.mntner},
	}
	idToken, err := p.sign(claims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": randomString(), "token_type": "Bearer",
		"expires_in": 3600, "id_token": idToken})
}

func (p *idp) sign(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "fake"))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(b)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
