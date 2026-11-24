// Package peercheck is the CI gate for the peers repository: it validates
// every DN42Peer file and decides whether a PR may be merged automatically.
// It uses the same validation as the operator (internal/peer), so the gate,
// the operator and the autopeer app agree on what a valid peer is.
package peercheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yamlv4 "go.yaml.in/yaml/v4"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/peer"
	"github.com/oscrx/dn42-operator/internal/registry"
)

// Change is one changed path in a PR. Renames are a delete plus an add.
type Change struct {
	Status byte // 'A' added, 'M' modified, 'D' deleted, 'T' type changed
	Path   string
}

// File is one file in a tree.
type File struct {
	Content []byte
	// Mode is the git mode ("100644"); only regular files are accepted.
	Mode string
}

// Input is what the check looks at.
type Input struct {
	// Head is the tree to validate (the PR head, or main), peers dir only.
	Head map[string]File
	// PR is nil for a plain tree check (push to main, local run).
	PR *PR
}

// PR describes a pull request.
type PR struct {
	Author  string
	Changes []Change
	// Base holds the base versions of the peer files the PR touches.
	Base map[string]File
}

// Options configure the check.
type Options struct {
	PeersDir  string   // default "peers"
	Namespace string   // allowed metadata.namespace besides none; default "dn42"
	AppLogins []string // PR authors that may auto-merge (the GitHub App bot)
	// Registry answers whether an ASN exists; nil fails every file unless
	// SkipRegistry is set.
	Registry     registry.ASNSource
	SkipRegistry bool
	// LocalASN is the router's own ASN, never a valid peer (0: unchecked).
	LocalASN int64
}

// Finding is one problem in one file ("" for the PR as a whole).
type Finding struct {
	File    string
	Message string
}

func (f Finding) String() string {
	if f.File == "" {
		return f.Message
	}
	return f.File + ": " + f.Message
}

// Result of a check.
type Result struct {
	Errors []Finding
	// NotAutoMergeable lists why a valid PR still needs a human merge.
	NotAutoMergeable []string
	AutoMergeable    bool
	Peers            int
}

// OK reports whether there are no errors.
func (r *Result) OK() bool { return len(r.Errors) == 0 }

func (r *Result) errorf(file, format string, args ...any) {
	r.Errors = append(r.Errors, Finding{File: file, Message: fmt.Sprintf(format, args...)})
}

var fileNameRe = regexp.MustCompile(`^(\d{1,10})-([a-z][a-z0-9]{0,11})\.yaml$`)

// peerFile is the only shape a peer file may have: no status, no labels,
// annotations or other metadata (an annotation could steer ArgoCD).
type peerFile struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   peerMeta            `json:"metadata"`
	Spec       dn42v1.DN42PeerSpec `json:"spec"`
}

type peerMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Parsed is a peer file that passed the per-file checks.
type Parsed struct {
	Path string
	Obj  dn42v1.DN42Peer
	Peer *peer.Peer
}

func (o *Options) defaults() {
	if o.PeersDir == "" {
		o.PeersDir = "peers"
	}
	o.PeersDir = strings.Trim(path.Clean(o.PeersDir), "/")
	if o.Namespace == "" {
		o.Namespace = "dn42"
	}
}

func (o *Options) inPeersDir(p string) bool {
	return strings.HasPrefix(p, o.PeersDir+"/")
}

// countDocuments counts the YAML documents in b.
func countDocuments(b []byte) (int, error) {
	dec := yamlv4.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var node yamlv4.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n++
	}
}

// ParseFile checks one peer file on its own.
func ParseFile(p string, f File, o *Options) (result *Parsed, problems []string) {
	opt := *o
	opt.defaults()
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if f.Mode != "" && f.Mode != "100644" && f.Mode != "100755" {
		add("not a regular file (git mode %s)", f.Mode)
		return nil, errs
	}
	if path.Dir(p) != opt.PeersDir {
		add("peer files must be directly in %s/", opt.PeersDir)
		return nil, errs
	}
	m := fileNameRe.FindStringSubmatch(path.Base(p))
	if m == nil {
		add("file name must be <asn>-<name>.yaml with name ^[a-z][a-z0-9]{0,11}$")
		return nil, errs
	}
	fileASN, _ := strconv.ParseInt(m[1], 10, 64)
	fileName := m[2]

	if len(f.Content) > 16<<10 {
		add("file is larger than 16 KiB")
		return nil, errs
	}
	n, err := countDocuments(f.Content)
	if err != nil {
		add("not valid YAML: %v", err)
		return nil, errs
	}
	if n != 1 {
		add("must contain exactly one YAML document, found %d", n)
		return nil, errs
	}
	var pf peerFile
	if err := peer.DecodeFile(f.Content, &pf); err != nil {
		add("schema: %v", err)
		return nil, errs
	}
	if pf.APIVersion != dn42v1.GroupVersion.String() || pf.Kind != "DN42Peer" {
		add("must be apiVersion %s, kind DN42Peer (got %s, %s)", dn42v1.GroupVersion, pf.APIVersion, pf.Kind)
	}
	if pf.Metadata.Namespace != "" && pf.Metadata.Namespace != opt.Namespace {
		add("namespace must be %s or unset, got %q", opt.Namespace, pf.Metadata.Namespace)
	}
	if pf.Metadata.Name != fileName {
		add("metadata.name %q does not match the file name (%q)", pf.Metadata.Name, fileName)
	}
	if pf.Spec.ASN != fileASN {
		add("spec.asn %d does not match the file name (%d)", pf.Spec.ASN, fileASN)
	}
	pp, verr := peer.FromSpec(pf.Metadata.Name, &pf.Spec)
	if verr != nil {
		add("%s", verr.Message)
	}
	if opt.LocalASN != 0 && pf.Spec.ASN == opt.LocalASN {
		add("AS%d is this router's own ASN: that session would be iBGP, not a peering", pf.Spec.ASN)
	}
	if !opt.SkipRegistry {
		switch {
		case opt.Registry == nil:
			add("no registry configured to check AS%d", pf.Spec.ASN)
		case !opt.Registry.Exists(pf.Spec.ASN):
			add("AS%d has no aut-num object in the DN42 registry", pf.Spec.ASN)
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	obj := dn42v1.DN42Peer{Spec: pf.Spec}
	obj.APIVersion, obj.Kind = pf.APIVersion, pf.Kind
	obj.Name, obj.Namespace = pf.Metadata.Name, pf.Metadata.Namespace
	return &Parsed{Path: p, Obj: obj, Peer: pp}, nil
}

// Check runs the whole gate.
func Check(in Input, o *Options) *Result {
	opt := *o
	opt.defaults()
	res := &Result{}

	// Every file in the peers dir, valid on its own.
	paths := make([]string, 0, len(in.Head))
	for p := range in.Head {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var parsed []*Parsed
	for _, p := range paths {
		if !opt.inPeersDir(p) {
			continue
		}
		if path.Base(p) == ".gitkeep" && path.Dir(p) == opt.PeersDir {
			continue
		}
		pf, errs := ParseFile(p, in.Head[p], &opt)
		for _, e := range errs {
			res.errorf(p, "%s", e)
		}
		if pf != nil {
			parsed = append(parsed, pf)
		}
	}
	res.Peers = len(parsed)

	// Across files. Files the PR doesn't touch claim their values first, so
	// a conflict is reported on the file the PR adds or changes.
	if in.PR != nil {
		touched := map[string]bool{}
		for _, c := range in.PR.Changes {
			touched[c.Path] = true
		}
		sort.SliceStable(parsed, func(i, j int) bool { return !touched[parsed[i].Path] && touched[parsed[j].Path] })
	}
	type asnNeighbor struct {
		asn uint32
		n   netip.Addr
	}
	names, ports := map[string]string{}, map[int]string{}
	neighbors := map[asnNeighbor]string{}
	for _, pf := range parsed {
		if other, ok := names[pf.Obj.Name]; ok {
			res.errorf(pf.Path, "name %q is already used by %s", pf.Obj.Name, other)
		} else {
			names[pf.Obj.Name] = pf.Path
		}
		if other, ok := ports[pf.Peer.ListenPort]; ok {
			res.errorf(pf.Path, "listen port %d is already used by %s", pf.Peer.ListenPort, other)
		} else {
			ports[pf.Peer.ListenPort] = pf.Path
		}
		k := asnNeighbor{pf.Peer.ASN, pf.Peer.Neighbor}
		if other, ok := neighbors[k]; ok {
			res.errorf(pf.Path, "AS%d with neighbor %s is already %s", k.asn, k.n, other)
		} else {
			neighbors[k] = pf.Path
		}
	}

	if in.PR == nil {
		return res
	}
	checkPR(in, &opt, res)
	return res
}

func checkPR(in Input, opt *Options, res *Result) {
	pr := in.PR
	isApp := false
	for _, l := range opt.AppLogins {
		if l != "" && pr.Author == l {
			isApp = true
		}
	}
	var outside, peerFiles []string
	seen := map[string]bool{}
	for _, c := range pr.Changes {
		if seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		if opt.inPeersDir(c.Path) {
			peerFiles = append(peerFiles, c.Path)
		} else {
			outside = append(outside, c.Path)
		}
	}
	sort.Strings(outside)
	sort.Strings(peerFiles)

	if len(outside) > 0 {
		if isApp {
			// The App only ever writes one peer file; anything else means
			// it is compromised or broken.
			for _, p := range outside {
				res.errorf(p, "the autopeer App may only change files in %s/", opt.PeersDir)
			}
		} else {
			res.NotAutoMergeable = append(res.NotAutoMergeable,
				fmt.Sprintf("changes outside %s/ need a human review: %s", opt.PeersDir, strings.Join(outside, ", ")))
		}
	}
	if !isApp {
		res.NotAutoMergeable = append(res.NotAutoMergeable, fmt.Sprintf("author %q is not the autopeer App", pr.Author))
	}
	if len(peerFiles) != 1 {
		res.NotAutoMergeable = append(res.NotAutoMergeable,
			fmt.Sprintf("auto-merge needs exactly one peer file changed, this PR changes %d", len(peerFiles)))
	}
	if isApp {
		// The App may change or delete any peer, but never set or change a
		// keyRef: that would point a peer at another key on our side. A
		// peer's keyRef (its own key, set by hand) stays as it is.
		for _, p := range peerFiles {
			h, inHead := in.Head[p]
			if !inHead {
				continue // deleted
			}
			headRef, ok := keyRefOf(h.Content)
			if !ok {
				continue // doesn't decode: already a schema error
			}
			baseRef := ""
			if b, inBase := pr.Base[p]; inBase {
				if baseRef, ok = keyRefOf(b.Content); !ok {
					res.errorf(p, "the base version does not decode, so a keyRef change can't be ruled out")
					continue
				}
			}
			if headRef != baseRef {
				res.errorf(p, "the autopeer App may not set or change keyRef")
			}
		}
	}
	res.AutoMergeable = res.OK() && len(res.NotAutoMergeable) == 0
}

// keyRefOf returns spec.keyRef; ok is false if the file doesn't parse.
func keyRefOf(b []byte) (string, bool) {
	// The same strict decode as the file check: what the cluster would read.
	var pf peerFile
	if err := peer.DecodeFile(b, &pf); err != nil {
		return "", false
	}
	return pf.Spec.KeyRef, true
}
