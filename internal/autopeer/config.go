// Package autopeer is the web front end for automatic peering: log in
// through a DN42 identity provider, prove ASN ownership, submit a peer, and
// get a PR in the peers repo plus the config for the peer's side.
package autopeer

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"sigs.k8s.io/yaml"

	"github.com/oscrx/dn42-operator/internal/peer"
)

// Config is the autopeer configuration file (YAML).
type Config struct {
	Listen string `json:"listen"`
	// PublicURL is the base URL users reach the app on; redirect URIs are
	// <publicURL>/auth/<provider>/callback.
	PublicURL string `json:"publicURL"`
	// ExtraPublicURLs are further hosts serving the same app (e.g. the
	// .dn42 name). A login uses the base whose host matches the request;
	// every base's callback must be registered with every provider.
	ExtraPublicURLs []string `json:"extraPublicURLs,omitempty"`
	// Limits on submissions (removals count too).
	Limits LimitsConfig `json:"limits"`
	// CookieKeyFile holds 32 random bytes (raw or base64) for the session
	// cookies (AES-GCM).
	CookieKeyFile string `json:"cookieKeyFile"`
	// SessionTTL is how long a login lasts (default 1h).
	SessionTTL Duration `json:"sessionTTL"`

	Router     RouterConfig     `json:"router"`
	Providers  []ProviderConfig `json:"providers"`
	Registry   RegistryConfig   `json:"registry"`
	GitHub     GitHubConfig     `json:"github"`
	Kubernetes KubeConfig       `json:"kubernetes"`
}

// LimitsConfig caps how many PRs the app opens.
type LimitsConfig struct {
	PerLoginPerHour int `json:"perLoginPerHour"` // default 3
	TotalPerHour    int `json:"totalPerHour"`    // default 20
}

// RouterConfig describes our side, shown in the peer's config.
type RouterConfig struct {
	ASN int64 `json:"asn"`
	// Name of our network, used for the interface/protocol names in the
	// peer's config (e.g. oscrx -> dn42-oscrx).
	Name string `json:"name"`
	// EndpointHost is the floating endpoint address (IP or hostname,
	// without port); the port is the peer's listenPort.
	EndpointHost string `json:"endpointHost"`
	// PublicKey is the shared autopeer WireGuard public key.
	PublicKey string `json:"publicKey"`
	// LinkLocal is our link-local address (default fe80::3818).
	LinkLocal string `json:"linkLocal"`
}

// ClaimsConfig says where a provider puts the identity. Paths may be dotted
// for nested claims ("dn42.asn"). Values may be a number, a string
// ("AS4242420001", "4242420001", comma or space separated) or a list.
type ClaimsConfig struct {
	Subject string `json:"subject"` // default "sub"
	ASN     string `json:"asn"`     // claim with the ASNs the user may manage
	Mntner  string `json:"mntner"`  // claim with mntner(s); ASNs come from the registry
}

// ProviderConfig is one OAuth 2.0 / OpenID Connect provider.
type ProviderConfig struct {
	Name        string `json:"name"` // in URLs: ^[a-z0-9]+$
	DisplayName string `json:"displayName"`
	// Issuer enables OpenID Connect discovery and ID token verification.
	// Without it, AuthURL/TokenURL/UserinfoURL are used (plain OAuth 2.0).
	Issuer      string `json:"issuer,omitempty"`
	AuthURL     string `json:"authURL,omitempty"`
	TokenURL    string `json:"tokenURL,omitempty"`
	UserinfoURL string `json:"userinfoURL,omitempty"`
	// UseUserinfo also merges the userinfo response into the claims for
	// OIDC providers (always used for plain OAuth).
	UseUserinfo      bool         `json:"useUserinfo,omitempty"`
	ClientID         string       `json:"clientID"`
	ClientSecretFile string       `json:"clientSecretFile,omitempty"` // empty: public client (PKCE only)
	Scopes           []string     `json:"scopes"`
	Claims           ClaimsConfig `json:"claims"`

	clientSecret string
}

// RegistryConfig points at a clone of the DN42 registry. It is only needed
// to map mntner claims to ASNs; with providers that return the ASN itself,
// leave Path empty and run without a registry (and without a clone).
type RegistryConfig struct {
	Path string `json:"path"` // contains data/aut-num; empty: no registry
	// Refresh reloads the registry from disk at this interval (0: never).
	Refresh Duration `json:"refresh"`
	// Pull runs "git pull --ff-only" before each reload. Leave it off when a
	// git-sync sidecar keeps the clone fresh (the image has no git).
	Pull bool `json:"pull"`
}

// GitHubConfig is the GitHub App that opens PRs in the peers repo.
type GitHubConfig struct {
	APIURL         string `json:"apiURL"` // default https://api.github.com
	Owner          string `json:"owner"`
	Repo           string `json:"repo"`
	BaseBranch     string `json:"baseBranch"` // default main
	PeersDir       string `json:"peersDir"`   // default peers
	AppID          int64  `json:"appID"`
	InstallationID int64  `json:"installationID"`
	// AppLogin is the App's bot user ("<app-slug>[bot]"). Only open PRs by
	// this login, from an autopeer/ branch in this repo, count as pending:
	// anyone can open a PR on a public repo.
	AppLogin       string `json:"appLogin"`
	PrivateKeyFile string `json:"privateKeyFile"`
}

// KubeConfig enables the status page (read-only DN42Peer status).
type KubeConfig struct {
	Enabled   bool   `json:"enabled"`
	Namespace string `json:"namespace"`
}

// Duration is a time.Duration in YAML ("1h").
type Duration struct{ time.Duration }

// UnmarshalJSON parses "1h30m".
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// LoadConfig reads and checks a config file, including the secret files.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.complete(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.ClientSecretFile != "" {
			s, err := os.ReadFile(p.ClientSecretFile)
			if err != nil {
				return nil, fmt.Errorf("provider %s: %w", p.Name, err)
			}
			p.clientSecret = strings.TrimSpace(string(s))
		}
	}
	return &c, nil
}

func (c *Config) complete() error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.SessionTTL.Duration == 0 {
		c.SessionTTL.Duration = time.Hour
	}
	if c.PublicURL == "" {
		return fmt.Errorf("publicURL is required")
	}
	var bases []string
	for _, u := range append([]string{c.PublicURL}, c.ExtraPublicURLs...) {
		u = strings.TrimRight(u, "/")
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || pu.Path != "" || pu.RawQuery != "" {
			return fmt.Errorf("public URL %q must be scheme://host with no path", u)
		}
		bases = append(bases, u)
	}
	c.PublicURL, c.ExtraPublicURLs = bases[0], bases[1:]
	if c.Limits.PerLoginPerHour == 0 {
		c.Limits.PerLoginPerHour = 3
	}
	if c.Limits.TotalPerHour == 0 {
		c.Limits.TotalPerHour = 20
	}
	if !peer.IsDN42ASN(c.Router.ASN) {
		return fmt.Errorf("router.asn %d is not a DN42 ASN", c.Router.ASN)
	}
	if peer.ValidateName(c.Router.Name) != nil {
		return fmt.Errorf("router.name %q must match ^[a-z][a-z0-9]{0,11}$", c.Router.Name)
	}
	if _, err := peer.ParseKey(c.Router.PublicKey); err != nil {
		return fmt.Errorf("router.publicKey: %w", err)
	}
	if c.Router.LinkLocal == "" {
		c.Router.LinkLocal = peer.DefaultLocalLinkLocal.String()
	}
	if _, err := peer.ParseLinkLocal(c.Router.LinkLocal); err != nil {
		return fmt.Errorf("router.linkLocal: %w", err)
	}
	if _, err := peer.ParseEndpoint(joinHostPort(c.Router.EndpointHost, 1)); err != nil {
		return fmt.Errorf("router.endpointHost: %w", err)
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("no providers")
	}
	seen := map[string]bool{}
	for i := range c.Providers {
		p := &c.Providers[i]
		if !providerNameRe.MatchString(p.Name) || seen[p.Name] {
			return fmt.Errorf("provider name %q must be unique and match %s", p.Name, providerNameRe)
		}
		seen[p.Name] = true
		if p.DisplayName == "" {
			p.DisplayName = p.Name
		}
		if p.ClientID == "" {
			return fmt.Errorf("provider %s: clientID is required", p.Name)
		}
		if p.Issuer == "" && (p.AuthURL == "" || p.TokenURL == "" || p.UserinfoURL == "") {
			return fmt.Errorf("provider %s: set issuer (OIDC) or authURL, tokenURL and userinfoURL (OAuth)", p.Name)
		}
		if p.Claims.Subject == "" {
			p.Claims.Subject = "sub"
		}
		if p.Claims.ASN == "" && p.Claims.Mntner == "" {
			return fmt.Errorf("provider %s: set claims.asn and/or claims.mntner", p.Name)
		}
		if p.Claims.Mntner != "" && c.Registry.Path == "" {
			return fmt.Errorf("provider %s: claims.mntner needs registry.path (mntners are mapped to ASNs through the registry)", p.Name)
		}
	}
	if c.GitHub.APIURL == "" {
		c.GitHub.APIURL = "https://api.github.com"
	}
	if c.GitHub.BaseBranch == "" {
		c.GitHub.BaseBranch = "main"
	}
	if c.GitHub.PeersDir == "" {
		c.GitHub.PeersDir = "peers"
	}
	if c.Kubernetes.Namespace == "" {
		c.Kubernetes.Namespace = "dn42"
	}
	return nil
}

// BaseFor returns the configured base URL whose host is host (the request's
// Host header), or the primary one. Only configured values are returned, so
// a forged Host header can't redirect a login elsewhere.
func (c *Config) BaseFor(host string) string {
	for _, b := range append([]string{c.PublicURL}, c.ExtraPublicURLs...) {
		if pu, err := url.Parse(b); err == nil && strings.EqualFold(pu.Host, host) {
			return b
		}
	}
	return c.PublicURL
}

// routerLinkLocal returns our link-local address.
func (c *Config) routerLinkLocal() netip.Addr {
	a, _ := peer.ParseLinkLocal(c.Router.LinkLocal)
	return a
}

func (c *Config) routerKey() wgtypes.Key {
	k, _ := peer.ParseKey(c.Router.PublicKey)
	return k
}
