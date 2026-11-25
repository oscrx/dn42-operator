// Package autopeer is the web front end for automatic peering: log in
// through a DN42 identity provider, prove ASN ownership, submit a peer, and
// get a PR in the peers repo plus the config for the peer's side.
package autopeer

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
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
	// CookieKeyFile holds 32 random bytes (base64) for the session
	// cookies (AES-GCM).
	CookieKeyFile string `json:"cookieKeyFile"`
	// SessionTTL is how long a login lasts without activity (default 1h);
	// every page view extends it.
	SessionTTL Duration `json:"sessionTTL"`
	// SessionMaxAge ends a login this long after logging in, however
	// active (default 12h).
	SessionMaxAge Duration `json:"sessionMaxAge"`

	Router     RouterConfig     `json:"router"`
	Providers  []ProviderConfig `json:"providers"`
	GitHub     GitHubConfig     `json:"github"`
	Kubernetes KubeConfig       `json:"kubernetes"`
	Admin      AdminConfig      `json:"admin"`
	// LookingGlass links each peering to its session in a bird-lg-go
	// looking glass. Optional.
	LookingGlass LookingGlassConfig `json:"lookingGlass"`
}

// LookingGlassConfig points at a bird-lg-go instance.
type LookingGlassConfig struct {
	URL    string `json:"url,omitempty"`    // e.g. https://lg.example.net
	Server string `json:"server,omitempty"` // its name for this router (BIRDLG_SERVERS)
	// HostURLs is the looking glass to link to from one of our public
	// hosts, e.g. its .dn42 name from the .dn42 host. Others use URL.
	HostURLs map[string]string `json:"hostURLs,omitempty"`
}

// LookingGlassFor is the looking glass base URL for pages on host ("" when
// none is configured).
func (c *Config) LookingGlassFor(host string) string {
	for h, u := range c.LookingGlass.HostURLs {
		if strings.EqualFold(h, host) {
			return u
		}
	}
	return c.LookingGlass.URL
}

// AdminConfig makes logins for the router's own ASN admins: they may add,
// edit and remove peerings for any DN42 ASN, through the same PRs (which
// auto-merge like any other). Off by default: an admin login is only as
// trustworthy as the providers that can issue it.
type AdminConfig struct {
	Enabled bool `json:"enabled"`
	// Providers that may grant admin (names from providers[]). Empty: all.
	Providers []string `json:"providers,omitempty"`
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
	Subject string `json:"subject"` // default "sub"; the stable key (rate limits)
	// Name is shown as the user's name (page header, PR body). Empty, or
	// missing from the claims: the subject. Never used as a key.
	Name string `json:"name,omitempty"`
	ASN  string `json:"asn"` // claim with the ASNs the user may manage
}

// ProviderConfig is one OAuth 2.0 / OpenID Connect provider.
type ProviderConfig struct {
	Name        string `json:"name"` // in URLs: ^[a-z0-9]+$
	DisplayName string `json:"displayName"`
	// Icon for the login button, as a data:image/ URI (so visitors' browsers
	// fetch nothing from the provider before they choose it). Empty: the
	// first letter of the display name.
	Icon string `json:"icon,omitempty"`
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
	// HostIssuers maps one of our public hosts to another issuer of the same
	// provider, used for logins started on that host: e.g. the .dn42 name
	// logs in through the provider's DN42-side address. OIDC only; the client
	// ID, secret and claims are shared.
	HostIssuers map[string]string `json:"hostIssuers,omitempty"`

	clientSecret string
}

// IssuerFor returns the issuer for logins started on host.
func (p *ProviderConfig) IssuerFor(host string) string {
	for h, iss := range p.HostIssuers {
		if strings.EqualFold(h, host) {
			return iss
		}
	}
	return p.Issuer
}

func (p *ProviderConfig) knowsIssuer(iss string) bool {
	if iss == p.Issuer {
		return true
	}
	for _, v := range p.HostIssuers {
		if v == iss {
			return true
		}
	}
	return false
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
	if c.SessionMaxAge.Duration == 0 {
		c.SessionMaxAge.Duration = 12 * time.Hour
	}
	if c.SessionMaxAge.Duration < c.SessionTTL.Duration {
		return fmt.Errorf("sessionMaxAge (%s) is shorter than sessionTTL (%s)", c.SessionMaxAge.Duration, c.SessionTTL.Duration)
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
		// One scheme for all: the session cookie's Secure flag follows it,
		// so a mix would break logins on one host or weaken the other's.
		if len(bases) > 0 && !strings.HasPrefix(u, strings.SplitN(bases[0], ":", 2)[0]+"://") {
			return fmt.Errorf("public URL %q: all public URLs must use the same scheme as %q", u, bases[0])
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
		if p.Icon != "" && !strings.HasPrefix(p.Icon, "data:image/") {
			return fmt.Errorf("provider %s: icon must be a data:image/ URI", p.Name)
		}
		if p.Issuer == "" && (p.AuthURL == "" || p.TokenURL == "" || p.UserinfoURL == "") {
			return fmt.Errorf("provider %s: set issuer (OIDC) or authURL, tokenURL and userinfoURL (OAuth)", p.Name)
		}
		if p.Claims.Subject == "" {
			p.Claims.Subject = "sub"
		}
		if p.Claims.ASN == "" {
			return fmt.Errorf("provider %s: claims.asn is required (the claim with the ASNs the login may manage)", p.Name)
		}
		for h, iss := range p.HostIssuers {
			if p.Issuer == "" {
				return fmt.Errorf("provider %s: hostIssuers needs an OIDC provider (issuer)", p.Name)
			}
			if !c.isPublicHost(h) {
				return fmt.Errorf("provider %s: hostIssuers: %q is not the host of publicURL or extraPublicURLs", p.Name, h)
			}
			if !isHTTPS(iss) {
				return fmt.Errorf("provider %s: hostIssuers[%s]: %q is not an https URL", p.Name, h, iss)
			}
		}
	}
	if lg := &c.LookingGlass; lg.URL != "" || len(lg.HostURLs) > 0 {
		if !isHTTPS(lg.URL) || !lgServerRe.MatchString(lg.Server) {
			return fmt.Errorf("lookingGlass: set url (https) and server")
		}
		lg.URL = strings.TrimRight(lg.URL, "/")
		for h, u := range lg.HostURLs {
			if !c.isPublicHost(h) || !isHTTPS(u) {
				return fmt.Errorf("lookingGlass.hostURLs: %q must be one of our hosts, mapped to an https URL", h)
			}
			lg.HostURLs[h] = strings.TrimRight(u, "/")
		}
	}
	for _, n := range c.Admin.Providers {
		if !seen[n] {
			return fmt.Errorf("admin.providers: no provider %q", n)
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

// IsAdmin reports whether id gets admin rights: admin enabled, the login
// shows the router's own ASN, and its provider may grant admin.
func (c *Config) IsAdmin(id *Identity) bool {
	if !c.Admin.Enabled || !id.holds(c.Router.ASN) {
		return false
	}
	if len(c.Admin.Providers) == 0 {
		return true
	}
	for _, n := range c.Admin.Providers {
		if n == id.Provider {
			return true
		}
	}
	return false
}

// lgServerRe is a looking glass server name: one URL path segment.
var lgServerRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

func isHTTPS(u string) bool {
	pu, err := url.Parse(u)
	return err == nil && pu.Scheme == "https" && pu.Host != ""
}

func (c *Config) isPublicHost(host string) bool {
	for _, b := range append([]string{c.PublicURL}, c.ExtraPublicURLs...) {
		if pu, err := url.Parse(b); err == nil && strings.EqualFold(pu.Host, host) {
			return true
		}
	}
	return false
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
