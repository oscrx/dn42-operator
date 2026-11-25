package autopeer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	ctrl "sigs.k8s.io/controller-runtime"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/peer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//go:embed templates/*.html
var templateFS embed.FS

// copyJS adds the copy buttons; served from our own origin so the CSP can
// stay at script-src 'self'.
//
//go:embed static/copy.js
var copyJS []byte

// copyJSPath carries a hash of the script, so a new version isn't served
// from a browser's cache.
var copyJSPath = func() string {
	h := sha256.Sum256(copyJS)
	return "/static/copy.js?v=" + hex.EncodeToString(h[:6])
}()

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

const (
	sessionCookie = "ap_session"
	flowCookie    = "ap_flow"
	flowTTL       = 10 * time.Minute
)

// StatusSource reads the live DN42Peer objects (for their status).
type StatusSource interface {
	Peers(ctx context.Context) ([]dn42v1.DN42Peer, error)
}

// Session is the login kept in the session cookie.
type Session struct {
	Identity Identity `json:"i"`
	CSRF     string   `json:"c"`
	// Started is when the user logged in (unix seconds), for
	// Config.SessionMaxAge; activity renews the cookie but not this.
	Started int64 `json:"s"`
}

// Server is the autopeer web app.
type Server struct {
	Cfg       *Config
	Providers map[string]*Provider
	Repo      PeerRepo
	Status    StatusSource // optional
	Cookies   *Cookies
	Limiter   *Limiter
}

// NewServer wires providers from the config.
func NewServer(cfg *Config, repo PeerRepo, status StatusSource, cookies *Cookies) *Server {
	s := &Server{Cfg: cfg, Providers: map[string]*Provider{}, Repo: repo, Status: status, Cookies: cookies,
		Limiter: &Limiter{PerKey: cfg.Limits.PerLoginPerHour, Total: cfg.Limits.TotalPerHour}}
	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		s.Providers[p.Name] = NewProvider(p)
	}
	return s
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login/{provider}", s.login)
	mux.HandleFunc("GET /auth/{provider}/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /peer/new", s.newPeer)
	mux.HandleFunc("POST /peer", s.submitPeer)
	mux.HandleFunc("GET /peer/remove", s.confirmRemove)
	mux.HandleFunc("POST /peer/remove", s.removePeer)
	mux.HandleFunc("GET /peer/edit", s.editPeerForm)
	mux.HandleFunc("POST /peer/edit", s.editPeer)
	mux.HandleFunc("GET /static/copy.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(copyJS)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return securityHeaders(s.slideSession(mux))
}

// renewAfter limits how often an active session's cookie is rewritten.
const renewAfter = 5 * time.Minute

// slideSession renews a valid session cookie on activity, so a login ends
// after SessionTTL without activity (or SessionMaxAge after logging in),
// not SessionTTL after logging in. The CSRF token stays, so an open form
// keeps working. Logout, the script and health checks don't renew.
func (s *Server) slideSession(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logout", "/healthz", "/static/copy.js":
		default:
			s.renew(w, r)
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var sess Session
	exp, err := s.Cookies.GetExp(r, sessionCookie, &sess)
	if err != nil || sess.Started == 0 {
		return
	}
	now := time.Now()
	ttl := s.Cfg.SessionTTL.Duration
	if left := time.Unix(sess.Started, 0).Add(s.Cfg.SessionMaxAge.Duration).Sub(now); left < ttl {
		ttl = left
	}
	// Only when it would move the expiry by at least renewAfter.
	if ttl <= 0 || now.Add(ttl).Sub(exp) < renewAfter {
		return
	}
	_ = s.Cookies.Set(w, sessionCookie, sess, ttl)
}

// maxBody caps every request body. The forms are a few hundred bytes; the
// cap applies before any handler (or logRefusal) parses a form, so nobody
// can make the app read a large body, logged in or not.
const maxBody = 16 << 10

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	data["RouterASN"] = s.Cfg.Router.ASN
	data["RouterName"] = s.Cfg.Router.Name
	data["CopyJS"] = copyJSPath
	data["OurLinkLocal"] = s.Cfg.routerLinkLocal().String()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		ctrl.Log.WithName("autopeer").Error(err, "render", "page", name)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.logRefusal(r, s.session(r), status, msg, "")
	s.render(w, status, "error.html", map[string]any{"Message": msg})
}

// logRefusal records why a request was refused (an error page or a form
// shown again with an error), so a visitor who gave up can be followed up
// on. It logs the reason and who was logged in, never the submitted form.
func (s *Server) logRefusal(r *http.Request, sess *Session, status int, msg, field string) {
	kv := []any{"method", r.Method, "path", r.URL.Path, "status", status, "reason", logText(msg)}
	if field != "" {
		kv = append(kv, "field", field)
	}
	// Only what the handler already parsed: parsing here would read the
	// body for requests refused before their form was looked at.
	if a := r.PostForm.Get("asn"); a != "" {
		kv = append(kv, "asn", logText(a))
	}
	if n := r.PostForm.Get("name"); n != "" {
		kv = append(kv, "peer", logText(n))
	} else if n := r.URL.Query().Get("name"); n != "" {
		kv = append(kv, "peer", logText(n))
	}
	if sess != nil {
		kv = append(kv, "provider", sess.Identity.Provider, "login", sess.Identity.Login(), "asns", sess.Identity.ASNs)
	}
	ctrl.Log.WithName("autopeer").Info("refused", kv...)
}

// logText keeps user-influenced text to one short line.
func logText(s string) string {
	s = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || unicode.In(c, unicode.Cf) {
			return ' '
		}
		return c
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func (s *Server) session(r *http.Request) *Session {
	var sess Session
	if err := s.Cookies.Get(r, sessionCookie, &sess); err != nil {
		return nil
	}
	if sess.Started == 0 || time.Since(time.Unix(sess.Started, 0)) > s.Cfg.SessionMaxAge.Duration {
		return nil // from before Started existed, or past the maximum
	}
	sess.Identity.Admin = s.Cfg.IsAdmin(&sess.Identity)
	return &sess
}

type providerLink struct {
	Name, DisplayName, Initial string
	Icon                       template.URL // validated data:image/ URI
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		var ps []providerLink
		for i := range s.Cfg.Providers {
			p := &s.Cfg.Providers[i]
			ps = append(ps, providerLink{Name: p.Name, DisplayName: p.DisplayName,
				Initial: strings.ToUpper(firstRune(p.DisplayName)), Icon: template.URL(p.Icon)}) //nolint:gosec // checked in Config.complete
		}
		s.render(w, http.StatusOK, "login.html", map[string]any{"Providers": ps})
		return
	}
	peers, err := s.ownPeers(r.Context(), &sess.Identity)
	data := map[string]any{"Session": sess, "Peers": peers,
		"LG": s.Cfg.LookingGlassFor(r.Host), "LGServer": s.Cfg.LookingGlass.Server}
	if err != nil {
		data["Error"] = "Could not load your peers right now."
		ctrl.Log.WithName("autopeer").Error(err, "list peers")
	}
	s.render(w, http.StatusOK, "home.html", data)
}

// PeerView is one of the user's peers on the home page.
type PeerView struct {
	Name, File  string
	ASN         int64
	ListenPort  int32
	Live        bool
	BGPState    string
	Handshake   string
	Routes      string
	Valid       string
	ValidReason string
	Transit     TransitView
	// Removable: no PR already pending for it (and the repo listing worked).
	Removable bool
	// PendingURL is an open PR for this peer.
	PendingURL string
}

// TransitView is the operator's transit probe result as a pill: whether TCP
// through the peer works when the replies come back via another network.
type TransitView struct {
	Label, Class string // "" when not probed
	Detail       string // the probe's per-target message
}

// transitView maps status.transit; a verdict awaiting confirmation keeps
// showing the verdict.
func transitView(st *dn42v1.TransitStatus) TransitView {
	switch {
	case st == nil || st.LastResult == "":
		return TransitView{}
	case st.Healthy == nil:
		return TransitView{Label: "checking", Detail: st.Message}
	case *st.Healthy:
		return TransitView{Label: "ok", Class: "ok", Detail: st.Message}
	default:
		return TransitView{Label: "broken", Class: "bad", Detail: st.Message}
	}
}

func (s *Server) ownPeers(ctx context.Context, id *Identity) ([]PeerView, error) {
	inRepo, err := s.Repo.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]dn42v1.DN42Peer{}
	if s.Status != nil {
		if objs, err := s.Status.Peers(ctx); err == nil {
			for i := range objs {
				live[objs[i].Name] = objs[i]
			}
		}
	}
	pendingByPath := map[string]Pending{}
	var pending []Pending
	if pending, err = s.Repo.PendingPeers(ctx); err == nil {
		for _, pd := range pending {
			pendingByPath[pd.Path] = pd
		}
	}
	var out []PeerView
	inRepoPaths := map[string]bool{}
	for i := range inRepo {
		p := &inRepo[i]
		if !id.May(p.Spec.ASN) {
			continue
		}
		v := PeerView{Name: p.Name, ASN: p.Spec.ASN, File: PeerFileName(s.Cfg.GitHub.PeersDir, p)}
		inRepoPaths[v.File] = true
		pd, isPending := pendingByPath[v.File]
		v.PendingURL = pd.URL
		v.Removable = !isPending && err == nil
		if p.Spec.ListenPort != nil {
			v.ListenPort = *p.Spec.ListenPort
		}
		if o, ok := live[p.Name]; ok && o.Spec.ASN == p.Spec.ASN {
			v.Live = true
			v.BGPState = o.Status.BGPState
			if o.Status.LastHandshake != nil {
				v.Handshake = time.Since(o.Status.LastHandshake.Time).Round(time.Second).String() + " ago"
			}
			if o.Status.RoutesImported != nil {
				v.Routes = strconv.FormatInt(*o.Status.RoutesImported, 10)
			}
			v.Transit = transitView(o.Status.Transit)
			for _, c := range o.Status.Conditions {
				if c.Type == dn42v1.ConditionValid {
					v.Valid, v.ValidReason = string(c.Status), c.Message
				}
			}
		}
		out = append(out, v)
	}
	// New peers still in review.
	for _, pd := range pending {
		if pd.Peer != nil && !inRepoPaths[pd.Path] && id.May(pd.Peer.Spec.ASN) {
			v := PeerView{Name: pd.Peer.Name, ASN: pd.Peer.Spec.ASN, File: pd.Path, PendingURL: pd.URL}
			if pd.Peer.Spec.ListenPort != nil {
				v.ListenPort = *pd.Peer.Spec.ListenPort
			}
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Providers[r.PathValue("provider")]
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Unknown login provider.")
		return
	}
	base := s.Cfg.BaseFor(r.Host)
	bu, _ := url.Parse(base)
	f := NewFlow(p.Config.Name, fmt.Sprintf("%s/auth/%s/callback", base, p.Config.Name), p.Config.IssuerFor(bu.Host))
	u, err := p.AuthCodeURL(r.Context(), f)
	if err != nil {
		ctrl.Log.WithName("autopeer").Error(err, "login")
		s.fail(w, r, http.StatusBadGateway, p.Config.DisplayName+" is not reachable right now.")
		return
	}
	if err := s.Cookies.Set(w, flowCookie, f, flowTTL); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not start the login.")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	name := r.PathValue("provider")
	p, ok := s.Providers[name]
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Unknown login provider.")
		return
	}
	var f Flow
	if err := s.Cookies.Get(r, flowCookie, &f); err != nil || f.Provider != name {
		s.fail(w, r, http.StatusBadRequest, "Login expired, please start again.")
		return
	}
	s.Cookies.Clear(w, flowCookie)
	if e := r.URL.Query().Get("error"); e != "" {
		s.fail(w, r, http.StatusUnauthorized, "Login was refused by "+p.Config.DisplayName+".")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(f.State)) != 1 {
		s.fail(w, r, http.StatusBadRequest, "Login state mismatch, please start again.")
		return
	}
	claims, err := p.Claims(r.Context(), &f, r.URL.Query().Get("code"))
	if err != nil {
		log.Error(err, "callback", "provider", name)
		s.fail(w, r, http.StatusUnauthorized, "Login with "+p.Config.DisplayName+" failed.")
		return
	}
	// Which claims the provider sent (names only, never values): enough to
	// map claims.* for a new provider without logging personal data.
	log.Info("claims", "provider", name, "names", claimNames(claims, ""))
	id, err := IdentityFromClaims(p.Config, claims)
	if err != nil {
		log.Info("login without ASN", "provider", name, "error", err.Error())
		s.fail(w, r, http.StatusForbidden, "Your login did not show any DN42 ASN you maintain.")
		return
	}
	id.Admin = s.Cfg.IsAdmin(id)
	sess := Session{Identity: *id, CSRF: randomString(24), Started: time.Now().Unix()}
	if err := s.Cookies.Set(w, sessionCookie, sess, s.Cfg.SessionTTL.Duration); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not save the session.")
		return
	}
	log.Info("login", "provider", name, "subject", id.Subject, "name", id.Name, "asns", id.ASNs, "admin", id.Admin)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) checkCSRF(r *http.Request, sess *Session) bool {
	return subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) == 1
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := s.session(r); sess != nil && s.checkCSRF(r, sess) {
		s.Cookies.Clear(w, sessionCookie)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) newPeer(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	name, neighbor := Suggest(s.Cfg, &sess.Identity)
	s.render(w, http.StatusOK, "form.html", map[string]any{"Session": sess, "Form": map[string]string{"name": name, "neighbor": neighbor},
		"Ours": s.ourSide(&sess.Identity)})
}

// OurSide is what a new peer configures for us, shown before they submit.
type OurSide struct {
	ASN       int64
	Endpoint  string // host, without port
	PublicKey string
	LinkLocal string
	MTU       int
	Ports     []ASNPort // our usual port for each of the login's ASNs (not for admins)
}

// ASNPort is our usual listen port for one ASN.
type ASNPort struct {
	ASN  int64
	Port int
}

func (s *Server) ourSide(id *Identity) OurSide {
	o := OurSide{ASN: s.Cfg.Router.ASN, Endpoint: s.Cfg.Router.EndpointHost, PublicKey: s.Cfg.routerKey().String(),
		LinkLocal: s.Cfg.routerLinkLocal().String(), MTU: peer.DefaultMTU}
	if !id.Admin {
		for _, a := range id.ASNs {
			if p, ok := peer.DefaultListenPort(a); ok && a != s.Cfg.Router.ASN {
				o.Ports = append(o.Ports, ASNPort{ASN: a, Port: p})
			}
		}
	}
	return o
}

// parseMTU reads the optional MTU field: 0 for empty (the default).
func parseMTU(v string) (int32, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < peer.MinMTU || n > peer.MaxMTU {
		return 0, false
	}
	return int32(n), true
}

// ourKey is our public key on a peer's link: what the operator reports in
// the live object's status, else (not live yet, live nil) the shared key.
func (s *Server) ourKey(live *dn42v1.DN42Peer) wgtypes.Key {
	if live != nil {
		if k, err := peer.ParseKey(live.Status.PublicKey); err == nil {
			return k
		}
	}
	return s.Cfg.routerKey()
}

// livePeer is the cluster's DN42Peer by name, nil if unknown.
func (s *Server) livePeer(ctx context.Context, name string) *dn42v1.DN42Peer {
	if s.Status == nil {
		return nil
	}
	objs, err := s.Status.Peers(ctx)
	if err != nil {
		return nil
	}
	for i := range objs {
		if objs[i].Name == name {
			return &objs[i]
		}
	}
	return nil
}

func (s *Server) submitPeer(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	sess := s.session(r)
	if sess == nil {
		s.fail(w, r, http.StatusUnauthorized, "You're not logged in: a login ends after a while without activity. Log in again; what you entered was not saved.")
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, sess) {
		s.fail(w, r, http.StatusForbidden, "The form expired, please reload it.")
		return
	}
	form := map[string]string{}
	for _, k := range []string{"asn", "name", "publicKey", "endpoint", "neighbor", "mtu"} {
		form[k] = r.PostFormValue(k)
	}
	again := func(msg, field string) {
		s.logRefusal(r, sess, http.StatusUnprocessableEntity, msg, field)
		s.render(w, http.StatusUnprocessableEntity, "form.html", map[string]any{
			"Session": sess, "Form": form, "Error": msg, "Field": field, "Ours": s.ourSide(&sess.Identity)})
	}
	asn, err := strconv.ParseInt(form["asn"], 10, 64)
	if err != nil {
		again("Enter an ASN.", "asn")
		return
	}
	mtu, ok := parseMTU(form["mtu"])
	if !ok {
		again(fmt.Sprintf("MTU must be a number from %d to %d, or empty for %d.", peer.MinMTU, peer.MaxMTU, peer.DefaultMTU), "mtu")
		return
	}
	existing, err := s.Repo.ListPeers(r.Context())
	if err != nil {
		log.Error(err, "list peers")
		s.fail(w, r, http.StatusServiceUnavailable, "Could not check the existing peers, please try later.")
		return
	}
	pending, err := s.Repo.PendingPeers(r.Context())
	if err != nil {
		log.Error(err, "pending peers")
		s.fail(w, r, http.StatusServiceUnavailable, "Could not check the pending requests, please try later.")
		return
	}
	// Peers in open PRs count as taken: same name, port or neighbor can't
	// be requested twice while one is in review.
	known := map[string]bool{}
	for i := range existing {
		known[existing[i].Name] = true
	}
	for _, pd := range pending {
		if pd.Peer != nil && !known[pd.Peer.Name] {
			existing = append(existing, *pd.Peer)
			known[pd.Peer.Name] = true
		}
	}
	req := Request{ASN: asn, Name: form["name"], PublicKey: form["publicKey"], Endpoint: form["endpoint"], Neighbor: form["neighbor"], MTU: mtu}
	obj, p, err := BuildPeer(s.Cfg, &sess.Identity, &req, existing)
	var fe *FieldError
	if errors.As(err, &fe) {
		again(fe.Message, fe.Field)
		return
	} else if err != nil {
		again(err.Error(), "form")
		return
	}
	content, err := PeerYAML(obj)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not render the peer file.")
		return
	}
	side, err := RenderPeerSide(s.Cfg, p, s.Cfg.routerKey()) // new: the shared key
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not render your config.")
		return
	}
	path := PeerFileName(s.Cfg.GitHub.PeersDir, obj)
	if !s.Limiter.Allow(sess.Identity.Provider + "/" + sess.Identity.Subject) {
		s.fail(w, r, http.StatusTooManyRequests, "Too many requests, please try again in an hour.")
		return
	}
	prURL, err := s.Repo.OpenPR(r.Context(), &PullRequest{
		Branch:  prBranch("", obj),
		Path:    path,
		Content: content,
		Title:   fmt.Sprintf("Add peer AS%d %s", obj.Spec.ASN, obj.Name),
		Body: fmt.Sprintf("Submitted through autopeer.\n\n- ASN: AS%d\n- Login: %s\n- Listen port: %d\n- File: %#q\n",
			obj.Spec.ASN, sess.Identity.Login(), *obj.Spec.ListenPort, path),
	})
	if err != nil {
		log.Error(err, "open PR", "peer", obj.Name)
		s.fail(w, r, http.StatusBadGateway, "Could not open the pull request, please try later.")
		return
	}
	log.Info("peer submitted", "peer", obj.Name, "asn", obj.Spec.ASN, "pr", prURL, "subject", sess.Identity.Subject, "name", sess.Identity.Name)
	s.render(w, http.StatusOK, "done.html", map[string]any{
		"Session": sess, "PR": prURL, "Peer": obj, "Side": side, "File": string(content)})
}

// ownAutopeer finds an autopeer of the login by name that has no open PR,
// or writes the error page and returns nil.
func (s *Server) ownAutopeer(w http.ResponseWriter, r *http.Request, sess *Session, name string) (target *dn42v1.DN42Peer, path string, peers []dn42v1.DN42Peer, pending []Pending) {
	peers, err := s.Repo.ListPeers(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "Could not load the peers, please try later.")
		return nil, "", nil, nil
	}
	for i := range peers {
		if peers[i].Name == name {
			target = &peers[i]
		}
	}
	// Same answer for "doesn't exist" and "not yours".
	if target == nil || !sess.Identity.May(target.Spec.ASN) {
		s.fail(w, r, http.StatusNotFound, "No such peering of yours.")
		return nil, "", nil, nil
	}
	path = PeerFileName(s.Cfg.GitHub.PeersDir, target)
	pending, err = s.Repo.PendingPeers(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "Could not check the pending requests, please try later.")
		return nil, "", nil, nil
	}
	for _, pd := range pending {
		if pd.Path == path {
			s.fail(w, r, http.StatusConflict, "There is already an open request for this peering: "+pd.URL)
			return nil, "", nil, nil
		}
	}
	return target, path, peers, pending
}

func (s *Server) postForm(w http.ResponseWriter, r *http.Request) *Session {
	sess := s.session(r)
	if sess == nil {
		s.fail(w, r, http.StatusUnauthorized, "You're not logged in: a login ends after a while without activity. Log in again; what you entered was not saved.")
		return nil
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, sess) {
		s.fail(w, r, http.StatusForbidden, "The form expired, please reload it.")
		return nil
	}
	return sess
}

// confirmRemove asks before removing a peering (the page runs no scripts,
// so no confirm() dialog).
func (s *Server) confirmRemove(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	target, _, _, _ := s.ownAutopeer(w, r, sess, r.URL.Query().Get("name"))
	if target == nil {
		return
	}
	s.render(w, http.StatusOK, "confirm-remove.html", map[string]any{"Session": sess, "Peer": target})
}

func (s *Server) removePeer(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	sess := s.postForm(w, r)
	if sess == nil {
		return
	}
	target, path, _, _ := s.ownAutopeer(w, r, sess, r.PostFormValue("name"))
	if target == nil {
		return
	}
	if !s.Limiter.Allow(sess.Identity.Provider + "/" + sess.Identity.Subject) {
		s.fail(w, r, http.StatusTooManyRequests, "Too many requests, please try again in an hour.")
		return
	}
	prURL, err := s.Repo.OpenPR(r.Context(), &PullRequest{
		Branch: prBranch("remove-", target),
		Path:   path,
		Delete: true,
		Title:  fmt.Sprintf("Remove peer AS%d %s", target.Spec.ASN, target.Name),
		Body: fmt.Sprintf("Removal requested through autopeer.\n\n- ASN: AS%d\n- Login: %s\n- File: %#q\n",
			target.Spec.ASN, sess.Identity.Login(), path),
	})
	if err != nil {
		log.Error(err, "open removal PR", "peer", target.Name)
		s.fail(w, r, http.StatusBadGateway, "Could not open the pull request, please try later.")
		return
	}
	log.Info("peer removal requested", "peer", target.Name, "asn", target.Spec.ASN, "pr", prURL, "subject", sess.Identity.Subject, "name", sess.Identity.Name)
	s.render(w, http.StatusOK, "removed.html", map[string]any{"Session": sess, "PR": prURL, "Name": target.Name})
}

func (s *Server) editPeerForm(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	target, _, _, _ := s.ownAutopeer(w, r, sess, r.URL.Query().Get("name"))
	if target == nil {
		return
	}
	s.renderEdit(w, r, http.StatusOK, sess, target, map[string]string{
		"publicKey": target.Spec.PublicKey, "endpoint": target.Spec.Endpoint, "neighbor": target.Spec.Neighbor,
		"mtu": mtuString(target)}, "")
}

// renderEdit shows a peering: its details and the peer's config as it is
// now, then the edit form.
func (s *Server) renderEdit(w http.ResponseWriter, r *http.Request, status int, sess *Session, target *dn42v1.DN42Peer, form map[string]string, errMsg string) {
	if errMsg != "" {
		s.logRefusal(r, sess, status, errMsg, "")
	}
	data := map[string]any{"Session": sess, "Peer": target, "Form": form, "Error": errMsg,
		"LG": s.Cfg.LookingGlassFor(r.Host), "LGServer": s.Cfg.LookingGlass.Server}
	live := s.livePeer(r.Context(), target.Name)
	if live != nil {
		data["Live"] = live
		data["Transit"] = transitView(live.Status.Transit)
	}
	if p, verr := peer.FromObject(target); verr == nil {
		data["Our"] = p
		data["OurEndpoint"] = joinHostPort(s.Cfg.Router.EndpointHost, p.ListenPort)
		if side, err := RenderPeerSide(s.Cfg, p, s.ourKey(live)); err == nil {
			data["Side"] = side
		}
	}
	s.render(w, status, "edit.html", data)
}

func mtuString(o *dn42v1.DN42Peer) string {
	if m := mtuOf(o); m != 0 {
		return strconv.Itoa(int(m))
	}
	return ""
}

func (s *Server) editPeer(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	sess := s.postForm(w, r)
	if sess == nil {
		return
	}
	target, path, peers, pending := s.ownAutopeer(w, r, sess, r.PostFormValue("name"))
	if target == nil {
		return
	}
	form := map[string]string{}
	for _, k := range []string{"publicKey", "endpoint", "neighbor", "mtu"} {
		form[k] = r.PostFormValue(k)
	}
	mtu, ok := parseMTU(form["mtu"])
	if !ok {
		s.renderEdit(w, r, http.StatusUnprocessableEntity, sess, target, form,
			fmt.Sprintf("MTU must be a number from %d to %d, or empty for %d.", peer.MinMTU, peer.MaxMTU, peer.DefaultMTU))
		return
	}
	others := append([]dn42v1.DN42Peer(nil), peers...)
	for _, pd := range pending {
		if pd.Peer != nil {
			others = append(others, *pd.Peer)
		}
	}
	obj, p, err := UpdatePeer(s.Cfg, &sess.Identity, target, &Request{PublicKey: form["publicKey"], Endpoint: form["endpoint"], Neighbor: form["neighbor"], MTU: mtu}, others)
	var fe *FieldError
	if errors.As(err, &fe) {
		s.renderEdit(w, r, http.StatusUnprocessableEntity, sess, target, form, fe.Message)
		return
	} else if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not update the peer.")
		return
	}
	content, err := PeerYAML(obj)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not render the peer file.")
		return
	}
	side, err := RenderPeerSide(s.Cfg, p, s.ourKey(s.livePeer(r.Context(), obj.Name)))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not render your config.")
		return
	}
	if !s.Limiter.Allow(sess.Identity.Provider + "/" + sess.Identity.Subject) {
		s.fail(w, r, http.StatusTooManyRequests, "Too many requests, please try again in an hour.")
		return
	}
	prURL, err := s.Repo.OpenPR(r.Context(), &PullRequest{
		Branch:  prBranch("edit-", obj),
		Path:    path,
		Content: content,
		Title:   fmt.Sprintf("Update peer AS%d %s", obj.Spec.ASN, obj.Name),
		Body: fmt.Sprintf("Update requested through autopeer.\n\n- ASN: AS%d\n- Login: %s\n- File: %#q\n",
			obj.Spec.ASN, sess.Identity.Login(), path),
	})
	if err != nil {
		log.Error(err, "open update PR", "peer", obj.Name)
		s.fail(w, r, http.StatusBadGateway, "Could not open the pull request, please try later.")
		return
	}
	log.Info("peer update requested", "peer", obj.Name, "asn", obj.Spec.ASN, "pr", prURL, "subject", sess.Identity.Subject, "name", sess.Identity.Name)
	s.render(w, http.StatusOK, "done.html", map[string]any{
		"Session": sess, "PR": prURL, "Peer": obj, "Side": side, "File": string(content)})
}

// prBranch names a PR's branch: autopeer/<kind><asn>-<name>-<random>.
func prBranch(kind string, p *dn42v1.DN42Peer) string {
	return fmt.Sprintf("autopeer/%s%d-%s-%s", kind, p.Spec.ASN, p.Name, randomString(4))
}

// mdCode renders untrusted text (the IdP subject) as a Markdown code span in
// PR bodies, so it can't mention users or add links.
func mdCode(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '`' || unicode.IsControl(r):
			return '\''
		case unicode.Is(unicode.Cf, r): // bidi overrides, zero-width characters
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 100 { // cut characters, not bytes
		s = string(r[:100])
	}
	return "`" + s + "`"
}

// firstRune is s's first character ("" for "").
func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}
