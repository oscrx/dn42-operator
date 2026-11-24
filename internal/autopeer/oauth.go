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
// A provider may use a different issuer per public host (hostIssuers), each
// with its own discovery and endpoints.
type Provider struct {
	Config *ProviderConfig
	// HTTPClient for discovery, token and userinfo calls (default: 10s timeout).
	HTTPClient *http.Client

	mu        sync.Mutex
	endpoints map[string]*endpoint // by issuer ("" for plain OAuth)
}

// endpoint is one issuer's discovered configuration.
type endpoint struct {
	oauth    oauth2.Config
	oidc     *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// NewProvider prepares a provider. The redirect URI is per flow, so one
// provider serves every public host.
func NewProvider(cfg *ProviderConfig) *Provider {
	return &Provider{Config: cfg, HTTPClient: &http.Client{Timeout: 10 * time.Second}, endpoints: map[string]*endpoint{}}
}

func (p *Provider) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, p.HTTPClient), p.HTTPClient)
}

// endpoint returns the (lazily discovered) endpoints for issuer. Only the
// configured issuers are accepted, so a flow cookie can't point elsewhere.
func (p *Provider) endpoint(ctx context.Context, issuer string) (*endpoint, error) {
	c := p.Config
	if !c.knowsIssuer(issuer) {
		return nil, fmt.Errorf("provider %s: issuer %q is not configured", c.Name, issuer)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.endpoints[issuer]; ok {
		return e, nil
	}
	e := &endpoint{oauth: oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.clientSecret,
		Scopes:       c.Scopes,
	}}
	if issuer != "" {
		op, err := oidc.NewProvider(p.ctx(ctx), issuer)
		if err != nil {
			return nil, fmt.Errorf("provider %s: discovery of %s: %w", c.Name, issuer, err)
		}
		e.oidc = op
		e.verifier = op.Verifier(&oidc.Config{ClientID: c.ClientID})
		e.oauth.Endpoint = op.Endpoint()
	} else {
		e.oauth.Endpoint = oauth2.Endpoint{AuthURL: c.AuthURL, TokenURL: c.TokenURL}
	}
	// Explicit URLs override discovery for the main issuer only.
	if issuer == c.Issuer {
		if c.AuthURL != "" {
			e.oauth.Endpoint.AuthURL = c.AuthURL
		}
		if c.TokenURL != "" {
			e.oauth.Endpoint.TokenURL = c.TokenURL
		}
	}
	p.endpoints[issuer] = e
	return e, nil
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
	// Issuer used for this login (the provider's issuer for that host).
	Issuer string `json:"i,omitempty"`
}

// NewFlow creates fresh state, PKCE verifier and nonce.
func NewFlow(provider, redirectURL, issuer string) *Flow {
	return &Flow{Provider: provider, State: randomString(24), Verifier: oauth2.GenerateVerifier(),
		Nonce: randomString(24), RedirectURL: redirectURL, Issuer: issuer}
}

// AuthCodeURL is where the user is sent to log in (Authorization Code with
// PKCE S256; plus a nonce for OIDC).
func (p *Provider) AuthCodeURL(ctx context.Context, f *Flow) (string, error) {
	e, err := p.endpoint(ctx, f.Issuer)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oauth2.SetAuthURLParam("redirect_uri", f.RedirectURL)}
	if e.oidc != nil {
		opts = append(opts, oidc.Nonce(f.Nonce))
	}
	return e.oauth.AuthCodeURL(f.State, opts...), nil
}

// Claims exchanges the code (with the PKCE verifier) and returns the
// identity claims: the verified ID token for OIDC, merged with userinfo when
// configured; userinfo alone for plain OAuth.
func (p *Provider) Claims(ctx context.Context, f *Flow, code string) (map[string]any, error) {
	e, err := p.endpoint(ctx, f.Issuer)
	if err != nil {
		return nil, err
	}
	cctx := p.ctx(ctx)
	tok, err := e.oauth.Exchange(cctx, code, oauth2.VerifierOption(f.Verifier), oauth2.SetAuthURLParam("redirect_uri", f.RedirectURL))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	claims := map[string]any{}
	if e.oidc != nil {
		raw, _ := tok.Extra("id_token").(string)
		if raw == "" {
			return nil, fmt.Errorf("no id_token in the token response")
		}
		idt, err := e.verifier.Verify(cctx, raw)
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
	ui, err := p.userinfo(cctx, e, tok)
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

func (p *Provider) userinfo(ctx context.Context, e *endpoint, tok *oauth2.Token) (map[string]any, error) {
	out := map[string]any{}
	if e.oidc != nil && p.Config.UserinfoURL == "" {
		ui, err := e.oidc.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("userinfo: %w", err)
		}
		err = ui.Claims(&out)
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Config.UserinfoURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	tok.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
