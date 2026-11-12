package autopeer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider is one configured login provider. OIDC discovery runs lazily on
// first use, so one unreachable provider doesn't keep the app from starting.
type Provider struct {
	Config *ProviderConfig
	// HTTPClient for discovery, token and userinfo calls (default: 10s timeout).
	HTTPClient *http.Client


	mu       sync.Mutex
	ready    bool
	oauth    oauth2.Config
	oidc     *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// NewProvider prepares a provider. The redirect URI is per flow, so one
// provider serves every public host.
func NewProvider(cfg *ProviderConfig) *Provider {
	return &Provider{Config: cfg, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

func (p *Provider) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, p.HTTPClient), p.HTTPClient)
}

func (p *Provider) init(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready {
		return nil
	}
	c := p.Config
	p.oauth = oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.clientSecret,
		Scopes:       c.Scopes,
	}
	if c.Issuer != "" {
		op, err := oidc.NewProvider(p.ctx(ctx), c.Issuer)
		if err != nil {
			return fmt.Errorf("provider %s: discovery: %w", c.Name, err)
		}
		p.oidc = op
		p.verifier = op.Verifier(&oidc.Config{ClientID: c.ClientID})
		p.oauth.Endpoint = op.Endpoint()
	} else {
		p.oauth.Endpoint = oauth2.Endpoint{AuthURL: c.AuthURL, TokenURL: c.TokenURL}
	}
	if c.AuthURL != "" {
		p.oauth.Endpoint.AuthURL = c.AuthURL
	}
	if c.TokenURL != "" {
		p.oauth.Endpoint.TokenURL = c.TokenURL
	}
	p.ready = true
	return nil
}

// Flow is the per-login state kept in a short-lived cookie.
type Flow struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Verifier string `json:"v"` // PKCE code verifier
	Nonce    string `json:"n"`
	// RedirectURL is the callback on the host the login started from; it
	// must be registered with the provider.
	RedirectURL string `json:"r"`
}

// NewFlow creates fresh state, PKCE verifier and nonce.
func NewFlow(provider, redirectURL string) *Flow {
	return &Flow{Provider: provider, State: randomString(24), Verifier: oauth2.GenerateVerifier(),
		Nonce: randomString(24), RedirectURL: redirectURL}
}

// AuthCodeURL is where the user is sent to log in (Authorization Code with
// PKCE S256; plus a nonce for OIDC).
func (p *Provider) AuthCodeURL(ctx context.Context, f *Flow) (string, error) {
	if err := p.init(ctx); err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oauth2.SetAuthURLParam("redirect_uri", f.RedirectURL)}
	if p.oidc != nil {
		opts = append(opts, oidc.Nonce(f.Nonce))
	}
	return p.oauth.AuthCodeURL(f.State, opts...), nil
}

// Claims exchanges the code (with the PKCE verifier) and returns the
// identity claims: the verified ID token for OIDC, merged with userinfo when
// configured; userinfo alone for plain OAuth.
func (p *Provider) Claims(ctx context.Context, f *Flow, code string) (map[string]any, error) {
	if err := p.init(ctx); err != nil {
		return nil, err
	}
	cctx := p.ctx(ctx)
	tok, err := p.oauth.Exchange(cctx, code, oauth2.VerifierOption(f.Verifier), oauth2.SetAuthURLParam("redirect_uri", f.RedirectURL))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	claims := map[string]any{}
	if p.oidc != nil {
		raw, _ := tok.Extra("id_token").(string)
		if raw == "" {
			return nil, fmt.Errorf("no id_token in the token response")
		}
		idt, err := p.verifier.Verify(cctx, raw)
		if err != nil {
			return nil, fmt.Errorf("id token: %w", err)
		}
		if idt.Nonce != f.Nonce {
			return nil, fmt.Errorf("id token nonce mismatch")
		}
		if err := idt.Claims(&claims); err != nil {
			return nil, err
		}
		if !p.Config.UseUserinfo {
			return claims, nil
		}
	}
	ui, err := p.userinfo(cctx, tok)
	if err != nil {
		return nil, err
	}
	for k, v := range ui {
		// The ID token's subject wins; everything else may come from userinfo.
		if _, ok := claims[k]; ok && k == "sub" {
			if claims[k] != v {
				return nil, fmt.Errorf("userinfo subject differs from the id token")
			}
			continue
		}
		claims[k] = v
	}
	return claims, nil
}

func (p *Provider) userinfo(ctx context.Context, tok *oauth2.Token) (map[string]any, error) {
	out := map[string]any{}
	if p.oidc != nil && p.Config.UserinfoURL == "" {
		ui, err := p.oidc.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("userinfo: %w", err)
		}
		return out, ui.Claims(&out)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Config.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	tok.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	return out, nil
}
