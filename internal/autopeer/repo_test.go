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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// fakeGitHub implements the few REST endpoints GitHubApp uses and checks
// the App JWT and installation token.
type fakeGitHub struct {
	t       *testing.T
	pub     *rsa.PublicKey
	mu      sync.Mutex
	files   map[string]string // path on main -> content
	refs    map[string]string
	added   map[string]string // branch/path -> content
	deleted map[string]bool   // branch/path
	pulls   []map[string]string
	calls   []string
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
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "inst-tok", "expires_at": time.Now().Add(time.Hour)})
			return
		}
		if auth != "token inst-tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		const base = "/repos/oscrx/dn42-peers"
		p := strings.TrimPrefix(r.URL.Path, base)
		switch {
		case r.Method == http.MethodGet && p == "/contents/peers":
			var out []map[string]string
			for path := range g.files {
				name := path[strings.LastIndex(path, "/")+1:]
				out = append(out, map[string]string{"type": "file", "name": name, "path": path})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/contents/peers/") && strings.HasPrefix(r.URL.Query().Get("ref"), "head-"):
			// A PR head: "head-<branch>".
			c, ok := g.added[strings.TrimPrefix(r.URL.Query().Get("ref"), "head-")+"/"+strings.TrimPrefix(p, "/contents/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "file", "content": base64.StdEncoding.EncodeToString([]byte(c))})
		case r.Method == http.MethodGet && p == "/pulls":
			var out []map[string]any
			for i, pl := range g.pulls {
				out = append(out, map[string]any{"number": i + 1, "html_url": "https://github.com/oscrx/dn42-peers/pull/" + strconv.Itoa(i+1),
					"user": map[string]string{"login": "dn42-autopeer[bot]"},
					"head": map[string]any{"sha": "head-" + pl["head"], "ref": pl["head"],
						"repo": map[string]string{"full_name": "oscrx/dn42-peers"}}})
			}
			// Anyone can open PRs on a public repo: a fork and a human PR
			// touching an existing peer must not count as pending.
			if r.URL.Query().Get("page") == "1" {
				out = append(out,
					map[string]any{"number": 900, "html_url": "https://github.com/oscrx/dn42-peers/pull/900",
						"user": map[string]string{"login": "dn42-autopeer[bot]"},
						"head": map[string]any{"sha": "x", "ref": "autopeer/evil", "repo": map[string]string{"full_name": "attacker/dn42-peers"}}},
					map[string]any{"number": 901, "html_url": "https://github.com/oscrx/dn42-peers/pull/901",
						"user": map[string]string{"login": "someone"},
						"head": map[string]any{"sha": "y", "ref": "autopeer/x", "repo": map[string]string{"full_name": "oscrx/dn42-peers"}}})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/pulls/") && strings.HasSuffix(p, "/files"):
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(p, "/pulls/"), "/files"))
			branch := g.pulls[n-1]["head"]
			var out []map[string]string
			for k := range g.added {
				if path, ok := strings.CutPrefix(k, branch+"/"); ok {
					out = append(out, map[string]string{"filename": path, "status": "added"})
				}
			}
			for k := range g.deleted {
				if path, ok := strings.CutPrefix(k, branch+"/"); ok {
					out = append(out, map[string]string{"filename": path, "status": "removed"})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			var in struct {
				Query     string `json:"query"`
				Variables struct {
					Input struct {
						Branch struct {
							Repo string `json:"repositoryNameWithOwner"`
							Name string `json:"branchName"`
						} `json:"branch"`
						ExpectedHeadOid string `json:"expectedHeadOid"`
						FileChanges     struct {
							Deletions []struct {
								Path string `json:"path"`
							} `json:"deletions"`
						} `json:"fileChanges"`
					} `json:"input"`
				} `json:"variables"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			v := in.Variables.Input
			if !strings.Contains(in.Query, "createCommitOnBranch") || v.Branch.Repo != "oscrx/dn42-peers" || v.ExpectedHeadOid == "" {
				_, _ = w.Write([]byte(`{"errors":[{"message":"bad request"}]}`))
				return
			}
			for _, d := range v.FileChanges.Deletions {
				if _, ok := g.files[d.Path]; !ok {
					_, _ = w.Write([]byte(`{"errors":[{"message":"no such file"}]}`))
					return
				}
				g.deleted[v.Branch.Name+"/"+d.Path] = true
			}
			_, _ = w.Write([]byte(`{"data":{"createCommitOnBranch":{"commit":{"oid":"c0ffee"}}}}`))
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/contents/peers/"):
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
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "file", "content": wrapped.String(), "sha": "blob-" + strings.TrimPrefix(p, "/contents/")})
		case r.Method == http.MethodGet && p == "/git/ref/heads/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "abc123"}})
		case r.Method == http.MethodPost && p == "/git/refs":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["sha"] != "abc123" {
				http.Error(w, "bad sha", http.StatusUnprocessableEntity)
				return
			}
			g.refs[in["ref"]] = in["sha"]
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		case r.Method == http.MethodPut && strings.HasPrefix(p, "/contents/"):
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			b, _ := base64.StdEncoding.DecodeString(in["content"])
			if _, ok := g.refs["refs/heads/"+in["branch"]]; !ok {
				http.Error(w, "no branch", http.StatusUnprocessableEntity)
				return
			}
			// Like GitHub: updating an existing file needs its sha.
			path := strings.TrimPrefix(p, "/contents/")
			if _, exists := g.files[path]; exists && in["sha"] != "blob-"+path {
				http.Error(w, "sha wasn't supplied", http.StatusUnprocessableEntity)
				return
			}
			g.added[in["branch"]+"/"+strings.TrimPrefix(p, "/contents/")] = string(b)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		case r.Method == http.MethodPost && p == "/pulls":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			g.pulls = append(g.pulls, in)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/oscrx/dn42-peers/pull/9"})
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
	_ = json.Unmarshal(b, &c)
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
		refs: map[string]string{}, added: map[string]string{}, deleted: map[string]bool{}}
	srv := httptest.NewServer(fg.handler())
	defer srv.Close()
	gh := &GitHubApp{Key: parsed, HTTPClient: srv.Client(), Cfg: GitHubConfig{APIURL: srv.URL, Owner: "oscrx", Repo: "dn42-peers",
		BaseBranch: "main", PeersDir: "peers", AppID: 1234, InstallationID: 77, AppLogin: "dn42-autopeer[bot]"}}

	peers, err := gh.ListPeers(t.Context())
	if err != nil || len(peers) != 1 || peers[0].Name != "old" || *peers[0].Spec.ListenPort != 20001 {
		t.Fatalf("list: %v %v", peers, err)
	}
	url, err := gh.OpenPR(t.Context(), &PullRequest{Branch: "autopeer/x", Path: "peers/4242420002-new.yaml",
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
	// Pending: the open PR adds peers/4242420002-new.yaml ("hello" doesn't
	// parse, so Peer is nil but the path is known).
	pend, err := gh.PendingPeers(t.Context())
	if err != nil || len(pend) != 1 || pend[0].Path != "peers/4242420002-new.yaml" || pend[0].Peer != nil ||
		pend[0].URL != "https://github.com/oscrx/dn42-peers/pull/1" {
		t.Fatalf("pending: %+v %v", pend, err)
	}
	// A removal PR: branch, a signed GraphQL commit deleting the file, PR.
	if _, err := gh.OpenPR(t.Context(), &PullRequest{Branch: "autopeer/rm", Path: "peers/4242420001-old.yaml", Delete: true, Title: "Remove"}); err != nil {
		t.Fatal(err)
	}
	if !fg.deleted["autopeer/rm/peers/4242420001-old.yaml"] {
		t.Errorf("deleted: %v", fg.deleted)
	}
	// A GraphQL error fails the PR.
	if _, err := gh.OpenPR(t.Context(), &PullRequest{Branch: "autopeer/rm2", Path: "peers/4242420099-none.yaml", Delete: true, Title: "Remove"}); err == nil ||
		!strings.Contains(err.Error(), "no such file") {
		t.Errorf("graphql error: %v", err)
	}
	// Updating an existing file sends its sha.
	if _, err := gh.OpenPR(t.Context(), &PullRequest{Branch: "autopeer/edit", Path: "peers/4242420001-old.yaml", Content: []byte("v2"), Title: "Update"}); err != nil {
		t.Fatal(err)
	}
	if fg.added["autopeer/edit/peers/4242420001-old.yaml"] != "v2" {
		t.Errorf("update not written: %v", fg.added)
	}

	// Now a parseable pending peer too.
	good, _ := PeerYAML(func() *dn42v1.DN42Peer { p := existingPeer("new", 4242420003, 20003, "fe80::3"); return &p }())
	fg.added["autopeer/x/peers/4242420002-new.yaml"] = string(good)
	pend, _ = gh.PendingPeers(t.Context())
	var sawRemove, sawNew bool
	for _, p := range pend {
		sawRemove = sawRemove || (p.Path == "peers/4242420001-old.yaml" && p.Peer == nil)
		sawNew = sawNew || (p.Peer != nil && p.Peer.Name == "new")
	}
	if !sawRemove || !sawNew {
		t.Errorf("pending: %+v", pend)
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

func TestGraphQLURL(t *testing.T) {
	for api, want := range map[string]string{
		"https://api.github.com":      "https://api.github.com/graphql",
		"https://ghe.example/api/v3/": "https://ghe.example/api/graphql",
	} {
		if got := (&GitHubApp{Cfg: GitHubConfig{APIURL: api}}).graphqlURL(); got != want {
			t.Errorf("%s: %s, want %s", api, got, want)
		}
	}
}
