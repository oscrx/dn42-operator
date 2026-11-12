package autopeer

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/registry"
)

//go:embed templates/*.html
var templateFS embed.FS

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
}

// Server is the autopeer web app.
type Server struct {
	Cfg       *Config
	Providers map[string]*Provider
	Registry  *registry.Registry
	Repo      PeerRepo
	Status    StatusSource // optional
	Cookies   *Cookies
}

// NewServer wires providers from the config.
func NewServer(cfg *Config, reg *registry.Registry, repo PeerRepo, status StatusSource, cookies *Cookies) *Server {
	s := &Server{Cfg: cfg, Providers: map[string]*Provider{}, Registry: reg, Repo: repo, Status: status, Cookies: cookies}
	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		s.Providers[p.Name] = NewProvider(p, fmt.Sprintf("%s/auth/%s/callback", cfg.PublicURL, p.Name))
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	data["RouterASN"] = s.Cfg.Router.ASN
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		ctrl.Log.WithName("autopeer").Error(err, "render", "page", name)
	}
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "error.html", map[string]any{"Message": msg})
}

func (s *Server) session(r *http.Request) *Session {
	var sess Session
	if err := s.Cookies.Get(r, sessionCookie, &sess); err != nil {
		return nil
	}
	return &sess
}

type providerLink struct{ Name, DisplayName string }

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		var ps []providerLink
		for _, p := range s.Cfg.Providers {
			ps = append(ps, providerLink{p.Name, p.DisplayName})
		}
		s.render(w, http.StatusOK, "login.html", map[string]any{"Providers": ps})
		return
	}
	peers, err := s.ownPeers(r.Context(), &sess.Identity)
	data := map[string]any{"Session": sess, "Peers": peers}
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
}

func (s *Server) ownPeers(ctx context.Context, id *Identity) ([]PeerView, error) {
	inRepo, err := s.Repo.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]dn42v1.DN42Peer{}
	if s.Status != nil {
		if objs, err := s.Status.Peers(ctx); err == nil {
			for _, o := range objs {
				live[o.Name] = o
			}
		}
	}
	var out []PeerView
	for _, p := range inRepo {
		if !id.May(p.Spec.ASN) {
			continue
		}
		v := PeerView{Name: p.Name, ASN: p.Spec.ASN, File: PeerFileName(s.Cfg.GitHub.PeersDir, &p)}
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
			for _, c := range o.Status.Conditions {
				if c.Type == dn42v1.ConditionValid {
					v.Valid, v.ValidReason = string(c.Status), c.Message
				}
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Providers[r.PathValue("provider")]
	if !ok {
		s.fail(w, http.StatusNotFound, "Unknown login provider.")
		return
	}
	f := NewFlow(p.Config.Name)
	u, err := p.AuthCodeURL(r.Context(), f)
	if err != nil {
		ctrl.Log.WithName("autopeer").Error(err, "login")
		s.fail(w, http.StatusBadGateway, p.Config.DisplayName+" is not reachable right now.")
		return
	}
	if err := s.Cookies.Set(w, flowCookie, f, flowTTL); err != nil {
		s.fail(w, http.StatusInternalServerError, "Could not start the login.")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	name := r.PathValue("provider")
	p, ok := s.Providers[name]
	if !ok {
		s.fail(w, http.StatusNotFound, "Unknown login provider.")
		return
	}
	var f Flow
	if err := s.Cookies.Get(r, flowCookie, &f); err != nil || f.Provider != name {
		s.fail(w, http.StatusBadRequest, "Login expired, please start again.")
		return
	}
	s.Cookies.Clear(w, flowCookie)
	if e := r.URL.Query().Get("error"); e != "" {
		s.fail(w, http.StatusUnauthorized, "Login was refused by "+p.Config.DisplayName+".")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(f.State)) != 1 {
		s.fail(w, http.StatusBadRequest, "Login state mismatch, please start again.")
		return
	}
	claims, err := p.Claims(r.Context(), &f, r.URL.Query().Get("code"))
	if err != nil {
		log.Error(err, "callback", "provider", name)
		s.fail(w, http.StatusUnauthorized, "Login with "+p.Config.DisplayName+" failed.")
		return
	}
	id, err := IdentityFromClaims(p.Config, claims, s.Registry)
	if err != nil {
		log.Info("login without ASN", "provider", name, "error", err.Error())
		s.fail(w, http.StatusForbidden, "Your login did not show any DN42 ASN you maintain.")
		return
	}
	sess := Session{Identity: *id, CSRF: randomString(24)}
	if err := s.Cookies.Set(w, sessionCookie, sess, s.Cfg.SessionTTL.Duration); err != nil {
		s.fail(w, http.StatusInternalServerError, "Could not save the session.")
		return
	}
	log.Info("login", "provider", name, "subject", id.Subject, "asns", id.ASNs)
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
	s.render(w, http.StatusOK, "form.html", map[string]any{"Session": sess, "Form": map[string]string{}})
}

func (s *Server) submitPeer(w http.ResponseWriter, r *http.Request) {
	log := ctrl.Log.WithName("autopeer")
	sess := s.session(r)
	if sess == nil {
		s.fail(w, http.StatusUnauthorized, "Please log in first.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, sess) {
		s.fail(w, http.StatusForbidden, "The form expired, please reload it.")
		return
	}
	form := map[string]string{}
	for _, k := range []string{"asn", "name", "publicKey", "endpoint", "neighbor"} {
		form[k] = r.PostFormValue(k)
	}
	again := func(msg, field string) {
		s.render(w, http.StatusUnprocessableEntity, "form.html", map[string]any{
			"Session": sess, "Form": form, "Error": msg, "Field": field})
	}
	asn, err := strconv.ParseInt(form["asn"], 10, 64)
	if err != nil {
		again("Pick one of your ASNs.", "asn")
		return
	}
	existing, err := s.Repo.ListPeers(r.Context())
	if err != nil {
		log.Error(err, "list peers")
		s.fail(w, http.StatusServiceUnavailable, "Could not check the existing peers, please try later.")
		return
	}
	req := Request{ASN: asn, Name: form["name"], PublicKey: form["publicKey"], Endpoint: form["endpoint"], Neighbor: form["neighbor"]}
	obj, p, err := BuildPeer(s.Cfg, &sess.Identity, req, existing)
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
		s.fail(w, http.StatusInternalServerError, "Could not render the peer file.")
		return
	}
	side, err := RenderPeerSide(s.Cfg, p)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "Could not render your config.")
		return
	}
	path := PeerFileName(s.Cfg.GitHub.PeersDir, obj)
	prURL, err := s.Repo.OpenPR(r.Context(), PullRequest{
		Branch:  fmt.Sprintf("autopeer/%d-%s-%s", obj.Spec.ASN, obj.Name, randomString(4)),
		Path:    path,
		Content: content,
		Title:   fmt.Sprintf("Add peer AS%d %s", obj.Spec.ASN, obj.Name),
		Body: fmt.Sprintf("Submitted through autopeer.\n\n- ASN: AS%d\n- Login: %s (%s)\n- Listen port: %d\n- File: `%s`\n",
			obj.Spec.ASN, sess.Identity.Subject, sess.Identity.Provider, *obj.Spec.ListenPort, path),
	})
	if err != nil {
		log.Error(err, "open PR", "peer", obj.Name)
		s.fail(w, http.StatusBadGateway, "Could not open the pull request, please try later.")
		return
	}
	log.Info("peer submitted", "peer", obj.Name, "asn", obj.Spec.ASN, "pr", prURL, "subject", sess.Identity.Subject)
	s.render(w, http.StatusOK, "done.html", map[string]any{
		"Session": sess, "PR": prURL, "Peer": obj, "Side": side, "File": string(content)})
}
