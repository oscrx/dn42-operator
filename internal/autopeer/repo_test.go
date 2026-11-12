package autopeer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// fakeGitHub implements the few REST endpoints GitHubApp uses and checks
// the App JWT and installation token.
type fakeGitHub struct {
	t     *testing.T
	pub   *rsa.PublicKey
	mu    sync.Mutex
	files map[string]string // path on main -> content
	refs  map[string]string
	added map[string]string // branch/path -> content
	pulls []map[string]string
	calls []string
}

func (g *fakeGitHub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.calls = append(g.calls, r.Method+" "+r.URL.Path)
		auth := r.Header.Get("Authorization")
		if r.URL.Path == "/app/installations/77/access_tokens" {
			if !g.checkJWT(strings.TrimPrefix(auth, "Bearer ")) {
				http.Error(w, "bad jwt", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"token": "inst-tok", "expires_at": time.Now().Add(time.Hour)})
			return
		}
		if auth != "token inst-tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		const base = "/repos/oscrx/dn42-peers"
		p := strings.TrimPrefix(r.URL.Path, base)
		switch {
		case r.Method == "GET" && p == "/contents/peers":
			var out []map[string]string
			for path := range g.files {
				name := path[strings.LastIndex(path, "/")+1:]
				out = append(out, map[string]string{"type": "file", "name": name, "path": path})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == "GET" && strings.HasPrefix(p, "/contents/peers/"):
			c, ok := g.files[strings.TrimPrefix(p, "/contents/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// GitHub wraps base64 at 60 columns.
			enc := base64.StdEncoding.EncodeToString([]byte(c))
			var wrapped strings.Builder
			for i := 0; i < len(enc); i += 60 {
				wrapped.WriteString(enc[i:min(i+60, len(enc))] + "\n")
			}
			json.NewEncoder(w).Encode(map[string]string{"type": "file", "content": wrapped.String()})
		case r.Method == "GET" && p == "/git/ref/heads/main":
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "abc123"}})
		case r.Method == "POST" && p == "/git/refs":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["sha"] != "abc123" {
				http.Error(w, "bad sha", 422)
				return
			}
			g.refs[in["ref"]] = in["sha"]
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		case r.Method == "PUT" && strings.HasPrefix(p, "/contents/"):
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			b, _ := base64.StdEncoding.DecodeString(in["content"])
			if _, ok := g.refs["refs/heads/"+in["branch"]]; !ok {
				http.Error(w, "no branch", 422)
				return
			}
			g.added[in["branch"]+"/"+strings.TrimPrefix(p, "/contents/")] = string(b)
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		case r.Method == "POST" && p == "/pulls":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			g.pulls = append(g.pulls, in)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/oscrx/dn42-peers/pull/9"})
		default:
			http.NotFound(w, r)
		}
	})
}

func (g *fakeGitHub) checkJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(g.pub, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	json.Unmarshal(b, &c)
	now := time.Now().Unix()
	return c.Iss == "1234" && c.Iat <= now && c.Exp > now && c.Exp-c.Iat <= 600
}

func TestGitHubApp(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	parsed, err := ParseRSAKey(pemKey)
	if err != nil {
		t.Fatal(err)
	}
	existing, _ := PeerYAML(func() *dn42v1.DN42Peer { p := existingPeer("old", 4242420001, 20001, "fe80::1"); return &p }())
	fg := &fakeGitHub{t: t, pub: &key.PublicKey, files: map[string]string{"peers/4242420001-old.yaml": string(existing)},
		refs: map[string]string{}, added: map[string]string{}}
	srv := httptest.NewServer(fg.handler())
	defer srv.Close()
	gh := &GitHubApp{Key: parsed, HTTPClient: srv.Client(), Cfg: GitHubConfig{APIURL: srv.URL, Owner: "oscrx", Repo: "dn42-peers",
		BaseBranch: "main", PeersDir: "peers", AppID: 1234, InstallationID: 77}}

	peers, err := gh.ListPeers(t.Context())
	if err != nil || len(peers) != 1 || peers[0].Name != "old" || *peers[0].Spec.ListenPort != 20001 {
		t.Fatalf("list: %v %v", peers, err)
	}
	url, err := gh.OpenPR(t.Context(), PullRequest{Branch: "autopeer/x", Path: "peers/4242420002-new.yaml",
		Content: []byte("hello"), Title: "Add peer", Body: "body"})
	if err != nil || url != "https://github.com/oscrx/dn42-peers/pull/9" {
		t.Fatalf("pr: %s %v", url, err)
	}
	if fg.added["autopeer/x/peers/4242420002-new.yaml"] != "hello" {
		t.Errorf("file: %v", fg.added)
	}
	if len(fg.pulls) != 1 || fg.pulls[0]["head"] != "autopeer/x" || fg.pulls[0]["base"] != "main" {
		t.Errorf("pulls: %v", fg.pulls)
	}
	// The installation token is fetched once and reused.
	n := 0
	for _, c := range fg.calls {
		if strings.HasSuffix(c, "/access_tokens") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("token fetched %d times", n)
	}

	// A wrong App key is refused by GitHub.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := &GitHubApp{Key: other, HTTPClient: srv.Client(), Cfg: gh.Cfg}
	if _, err := bad.ListPeers(t.Context()); err == nil {
		t.Error("wrong key accepted")
	}
}
