package autopeer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/yaml"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// PullRequest is a change adding, changing or (Delete) removing one peer file.
type PullRequest struct {
	Branch  string
	Path    string
	Content []byte
	Delete  bool
	Title   string
	Body    string
}

// Pending is a peer file changed by an open PR.
type Pending struct {
	URL  string
	Path string
	// Peer is the file in the PR; nil when the PR deletes it or it doesn't
	// parse (the gate rejects those anyway).
	Peer *dn42v1.DN42Peer
}

// PeerRepo is the peers repository (oscrx/dn42-peers).
type PeerRepo interface {
	// ListPeers returns the DN42Peer files on the base branch.
	ListPeers(ctx context.Context) ([]dn42v1.DN42Peer, error)
	// OpenPR creates a branch with the change and opens a PR; returns its URL.
	OpenPR(ctx context.Context, pr PullRequest) (string, error)
	// PendingPeers lists the peer files touched by open PRs, so a second
	// request can't take a name, port or neighbor that is still in review.
	PendingPeers(ctx context.Context) ([]Pending, error)
}

// ParsePeerFile parses one peer file strictly.
func ParsePeerFile(b []byte) (*dn42v1.DN42Peer, error) {
	var p dn42v1.DN42Peer
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		return nil, err
	}
	if p.Kind != "DN42Peer" || p.APIVersion != dn42v1.GroupVersion.String() {
		return nil, fmt.Errorf("not a %s DN42Peer", dn42v1.GroupVersion)
	}
	return &p, nil
}

// FakeRepo is an in-memory PeerRepo for tests and local runs.
type FakeRepo struct {
	mu    sync.Mutex
	Files map[string][]byte // path -> content on the base branch
	PRs   []PullRequest
}

// ListPeers parses every *.yaml file.
func (f *FakeRepo) ListPeers(context.Context) ([]dn42v1.DN42Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for n := range f.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []dn42v1.DN42Peer
	for _, n := range names {
		if !strings.HasSuffix(n, ".yaml") {
			continue
		}
		p, err := ParsePeerFile(f.Files[n])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, *p)
	}
	return out, nil
}

// OpenPR records the PR.
func (f *FakeRepo) OpenPR(_ context.Context, pr PullRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.PRs {
		if p.Branch == pr.Branch {
			return "", fmt.Errorf("branch %s exists", pr.Branch)
		}
	}
	f.PRs = append(f.PRs, pr)
	return fmt.Sprintf("https://github.com/example/peers/pull/%d", len(f.PRs)), nil
}

// PendingPeers treats every recorded PR as open.
func (f *FakeRepo) PendingPeers(context.Context) ([]Pending, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Pending
	for i, pr := range f.PRs {
		p := Pending{URL: fmt.Sprintf("https://github.com/example/peers/pull/%d", i+1), Path: pr.Path}
		if !pr.Delete {
			if obj, err := ParsePeerFile(pr.Content); err == nil {
				p.Peer = obj
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// GitHubApp is a PeerRepo using the GitHub REST API as a GitHub App
// installation (contents and pull requests on the one repo).
type GitHubApp struct {
	Cfg        GitHubConfig
	Key        *rsa.PrivateKey
	HTTPClient *http.Client
	Now        func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewGitHubApp loads the App's private key.
func NewGitHubApp(cfg GitHubConfig) (*GitHubApp, error) {
	b, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := ParseRSAKey(b)
	if err != nil {
		return nil, err
	}
	return &GitHubApp{Cfg: cfg, Key: key, HTTPClient: &http.Client{Timeout: 20 * time.Second}}, nil
}

// ParseRSAKey parses a PEM RSA key (PKCS#1, as GitHub issues them, or PKCS#8).
func ParseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block in the GitHub App key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App key is not RSA")
	}
	return rk, nil
}

func (g *GitHubApp) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// appJWT is the RS256 JWT that authenticates as the App.
func (g *GitHubApp) appJWT() (string, error) {
	enc := base64.RawURLEncoding
	hdr := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	now := g.now()
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": fmt.Sprint(g.Cfg.AppID),
	})
	signing := hdr + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

func (g *GitHubApp) installationToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && g.now().Before(g.tokenExp.Add(-time.Minute)) {
		return g.token, nil
	}
	jwt, err := g.appJWT()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := g.do(ctx, "Bearer "+jwt, http.MethodPost,
		fmt.Sprintf("/app/installations/%d/access_tokens", g.Cfg.InstallationID), nil, &out); err != nil {
		return "", fmt.Errorf("installation token: %w", err)
	}
	g.token, g.tokenExp = out.Token, out.ExpiresAt
	return g.token, nil
}

// HTTPError is a non-2xx GitHub response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Body) }

func (g *GitHubApp) do(ctx context.Context, auth, method, p string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.Cfg.APIURL, "/")+p, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (g *GitHubApp) api(ctx context.Context, method, p string, in, out any) error {
	tok, err := g.installationToken(ctx)
	if err != nil {
		return err
	}
	return g.do(ctx, "token "+tok, method, p, in, out)
}

func (g *GitHubApp) repoPath(format string, args ...any) string {
	return fmt.Sprintf("/repos/%s/%s", url.PathEscape(g.Cfg.Owner), url.PathEscape(g.Cfg.Repo)) + fmt.Sprintf(format, args...)
}

type contentEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA     string `json:"sha"`
}

// ListPeers reads every *.yaml in the peers dir on the base branch.
func (g *GitHubApp) ListPeers(ctx context.Context) ([]dn42v1.DN42Peer, error) {
	ref := url.QueryEscape(g.Cfg.BaseBranch)
	var entries []contentEntry
	err := g.api(ctx, http.MethodGet, g.repoPath("/contents/%s?ref=%s", escapePath(g.Cfg.PeersDir), ref), nil, &entries)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		return nil, nil // no peers dir yet
	}
	if err != nil {
		return nil, err
	}
	var out []dn42v1.DN42Peer
	for _, e := range entries {
		if e.Type != "file" || !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		var f contentEntry
		if err := g.api(ctx, http.MethodGet, g.repoPath("/contents/%s?ref=%s", escapePath(e.Path), ref), nil, &f); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path, err)
		}
		p, err := ParsePeerFile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path, err)
		}
		out = append(out, *p)
	}
	return out, nil
}

// OpenPR: branch from the base head, add the file, open the PR.
func (g *GitHubApp) OpenPR(ctx context.Context, pr PullRequest) (string, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.api(ctx, http.MethodGet, g.repoPath("/git/ref/heads/%s", escapePath(g.Cfg.BaseBranch)), nil, &ref); err != nil {
		return "", fmt.Errorf("base branch: %w", err)
	}
	if err := g.api(ctx, http.MethodPost, g.repoPath("/git/refs"),
		map[string]string{"ref": "refs/heads/" + pr.Branch, "sha": ref.Object.SHA}, nil); err != nil {
		return "", fmt.Errorf("create branch: %w", err)
	}
	if pr.Delete {
		var cur contentEntry
		if err := g.api(ctx, http.MethodGet, g.repoPath("/contents/%s?ref=%s", escapePath(pr.Path), url.QueryEscape(pr.Branch)), nil, &cur); err != nil {
			return "", fmt.Errorf("find file: %w", err)
		}
		if err := g.api(ctx, http.MethodDelete, g.repoPath("/contents/%s", escapePath(pr.Path)), map[string]string{
			"message": pr.Title, "sha": cur.SHA, "branch": pr.Branch,
		}, nil); err != nil {
			return "", fmt.Errorf("delete file: %w", err)
		}
	} else if err := g.api(ctx, http.MethodPut, g.repoPath("/contents/%s", escapePath(pr.Path)), map[string]string{
		"message": pr.Title,
		"content": base64.StdEncoding.EncodeToString(pr.Content),
		"branch":  pr.Branch,
	}, nil); err != nil {
		return "", fmt.Errorf("add file: %w", err)
	}
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	if err := g.api(ctx, http.MethodPost, g.repoPath("/pulls"), map[string]string{
		"title": pr.Title, "head": pr.Branch, "base": g.Cfg.BaseBranch, "body": pr.Body,
	}, &out); err != nil {
		return "", fmt.Errorf("open PR: %w", err)
	}
	return out.HTMLURL, nil
}

// PendingPeers reads the open PRs and the peer files they change (at the
// PR head).
func (g *GitHubApp) PendingPeers(ctx context.Context) ([]Pending, error) {
	var pulls []struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := g.api(ctx, http.MethodGet, g.repoPath("/pulls?state=open&per_page=100"), nil, &pulls); err != nil {
		return nil, fmt.Errorf("open PRs: %w", err)
	}
	var out []Pending
	for _, pl := range pulls {
		var files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}
		if err := g.api(ctx, http.MethodGet, g.repoPath("/pulls/%d/files?per_page=100", pl.Number), nil, &files); err != nil {
			return nil, fmt.Errorf("files of PR %d: %w", pl.Number, err)
		}
		for _, f := range files {
			if !strings.HasPrefix(f.Filename, strings.TrimRight(g.Cfg.PeersDir, "/")+"/") {
				continue
			}
			p := Pending{URL: pl.HTMLURL, Path: f.Filename}
			if f.Status != "removed" && strings.HasSuffix(f.Filename, ".yaml") {
				var c contentEntry
				if err := g.api(ctx, http.MethodGet, g.repoPath("/contents/%s?ref=%s", escapePath(f.Filename), url.QueryEscape(pl.Head.SHA)), nil, &c); err == nil {
					if b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(c.Content, "\n", "")); err == nil {
						if obj, err := ParsePeerFile(b); err == nil {
							p.Peer = obj
						}
					}
				}
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func escapePath(p string) string {
	parts := strings.Split(path.Clean(p), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
