// Package controller holds the reconcile pass, the status loop and the
// leader election of dn42-operator.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/netdev"
	"github.com/oscrx/dn42-operator/internal/peer"
)

// FieldOwner is the server-side apply field manager for the Service ports.
const FieldOwner = "dn42-operator"

// ConfirmDeletionsKey is the key in the control ConfigMap that confirms a
// blocked mass deletion: set it to the number of links to delete.
const ConfirmDeletionsKey = "confirmDeletions"

// StandDownKey in the control ConfigMap, set to "true", makes the leader
// remove all managed links and peer snippets and stay that way (not ready)
// until the key is removed: the first step of a rollback to another setup,
// or of maintenance.
const StandDownKey = "standDown"

// errNotLeader aborts a pass whose term ended while it ran.
var errNotLeader = errors.New("no longer the leader, pass aborted")

// Tunnel reasons for the TunnelReady condition.
const (
	ReasonHandshake         = "Handshake"
	ReasonNoHandshake       = "NoHandshake"
	ReasonInvalid           = "Invalid"
	ReasonKeyMissing        = "KeyMissing"
	ReasonInterfaceConflict = "InterfaceConflict"
	ReasonVRFMissing        = "VRFMissing"
	ReasonLinkError         = "LinkError"
)

// BirdControl is the BIRD client the reconciler needs.
type BirdControl interface {
	ShowProtocols(ctx context.Context) (map[string]bird.ProtocolStatus, error)
}

// Resolver resolves a peer endpoint to a UDP address.
type Resolver func(ctx context.Context, ep *peer.Endpoint) (*net.UDPAddr, error)

// peerResult is what the last pass found for one object; the status loop
// turns it into the object's status.
type peerResult struct {
	generation int64
	asn        int64
	iface      string
	listenPort int32
	publicKey  string // ours on this link
	link       *dn42v1.LinkValues

	valid       bool
	validReason string
	validMsg    string

	tunnelConfigured bool
	tunnelReason     string
	tunnelMsg        string
}

// Reconciler runs the whole reconcile as one pass over all peers: the checks
// across objects, cleanup, BIRD reload and Service ports all need the full
// set, so every event enqueues the same key.
type Reconciler struct {
	Client    client.Client // cached
	APIReader client.Reader // uncached, for the Service and control ConfigMap
	Namespace string

	KeySecret     string // Secret with the private keys
	SharedKeyName string // key in KeySecret for peers without keyRef
	VRF           string

	EndpointService   string  // Service whose spec.ports we own; "" = none
	ControlConfigMap  string  // ConfigMap to confirm mass deletion; "" = none
	MaxDeleteFraction float64 // block a pass deleting more than this share of links

	NetDev   netdev.Manager
	Dir      *bird.Dir
	Bird     BirdControl
	Renderer bird.Renderer
	Resolve  Resolver

	State *RoleState
	// Labeler keeps the leader label on our own pod; nil disables it.
	Labeler *PodLabeler
	// Events receives a value whenever a pass should run.
	Events chan struct{}
	// StatusNow is signalled after each pass so status is written promptly.
	StatusNow chan struct{}

	Now func() time.Time

	mu       sync.Mutex
	results  map[string]*peerResult
	lastPass error
	passed   bool
	// standingDown is true while the control ConfigMap says standDown.
	standingDown bool

	cancelMu   sync.Mutex
	passCancel context.CancelFunc
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Trigger asks for a pass without blocking.
func (r *Reconciler) Trigger() {
	select {
	case r.Events <- struct{}{}:
	default:
	}
}

func metaFor(ns, name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: ns, Name: name} }

// Reconcile runs one pass and schedules the next full pass in 60s (10s
// after a failed pass).
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	err := r.Pass(ctx)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "pass failed, nothing more changed")
		// Retried on a short timer, not with backoff, so an API outage
		// doesn't spin and BIRD starting after the operator is picked up
		// quickly.
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}
	return reconcile.Result{RequeueAfter: 60 * time.Second}, nil
}

// Ready reports whether this replica is healthy in its role: the last pass
// completed and, with a Labeler, the leader label on our pod is known to
// match the role. A healthy follower is Ready too (so DaemonSet rolling
// updates proceed); the endpoint Service selects on the leader label, so it
// still receives no traffic.
func (r *Reconciler) Ready() error {
	role := r.State.Get()
	if role != RoleLeader && role != RoleFollower {
		return fmt.Errorf("role is %s", role)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.passed {
		return errors.New("no pass completed yet")
	}
	if r.standingDown {
		return errors.New("standing down (control ConfigMap)")
	}
	if r.lastPass != nil {
		return fmt.Errorf("last %s pass failed: %w", role, r.lastPass)
	}
	if r.Labeler != nil {
		v, ok := r.Labeler.Confirmed()
		if !ok || v != (role == RoleLeader) {
			return fmt.Errorf("leader label on own pod not confirmed for role %s", role)
		}
	}
	return nil
}

// Pass runs one reconcile pass for the current role.
func (r *Reconciler) Pass(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	mPasses.Inc()
	// The elector cancels this when the lease is lost or the pod stops, so
	// Teardown never waits behind slow BIRD or DNS calls.
	ctx, cancel := context.WithCancel(ctx)
	r.cancelMu.Lock()
	r.passCancel = cancel
	r.cancelMu.Unlock()
	defer func() {
		r.cancelMu.Lock()
		r.passCancel = nil
		r.cancelMu.Unlock()
		cancel()
	}()
	var err error
	switch r.State.Get() {
	case RoleLeader:
		if r.standDownRequested(ctx) {
			if !r.standingDown {
				ctrl.LoggerFrom(ctx).Info("standing down: control ConfigMap says " + StandDownKey)
			}
			r.standingDown = true
			err = r.teardownLocked(ctx)
			break
		}
		r.standingDown = false
		err = r.leaderPass(ctx)
		// Label whatever the pass result (readiness reflects health), but
		// only while still leading: a term may end during a pass.
		if r.Labeler != nil && r.State.Get() == RoleLeader {
			err = errors.Join(err, r.Labeler.ClearOthers(ctx), r.Labeler.Set(ctx, true))
		}
	case RoleFollower:
		err = r.teardownLocked(ctx)
	default:
		// Unknown or stopping: touch nothing.
		return nil
	}
	r.lastPass = err
	r.passed = true
	select {
	case r.StatusNow <- struct{}{}:
	default:
	}
	return err
}

// CancelPass aborts a pass in progress (its context is cancelled).
func (r *Reconciler) CancelPass() {
	r.cancelMu.Lock()
	defer r.cancelMu.Unlock()
	if r.passCancel != nil {
		r.passCancel()
	}
}

func (r *Reconciler) standDownRequested(ctx context.Context) bool {
	if r.ControlConfigMap == "" || r.APIReader == nil {
		return false
	}
	var cm corev1.ConfigMap
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.ControlConfigMap}, &cm); err != nil {
		return false
	}
	return cm.Data[StandDownKey] == "true"
}

// Teardown removes every managed link and peer config, regardless of the
// mass-deletion guard: this replica is standing down on purpose.
func (r *Reconciler) Teardown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.teardownLocked(ctx)
}

func (r *Reconciler) teardownLocked(ctx context.Context) error {
	log := ctrl.LoggerFrom(ctx)
	r.results = nil
	var errs []error
	links, err := r.NetDev.ListManaged()
	if err != nil {
		errs = append(errs, err)
	}
	for i := range links {
		l := &links[i]
		if err := r.NetDev.Delete(l.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		mLinkChanges.WithLabelValues("delete").Inc()
		log.Info("removed link (standing down)", "link", l.Name)
	}
	if removed, err := r.Dir.Clear(ctx); err != nil {
		errs = append(errs, fmt.Errorf("bird: %w", err))
	} else if len(removed) > 0 {
		log.Info("removed peer configs (standing down)", "peers", removed)
	}
	if r.Labeler != nil {
		errs = append(errs, r.Labeler.Set(ctx, false))
	}
	return errors.Join(errs...)
}

func (r *Reconciler) leaderPass(ctx context.Context) error {
	log := ctrl.LoggerFrom(ctx)
	now := r.now()

	// Safety: a failed list is never "no peers".
	var list dn42v1.DN42PeerList
	if err := r.Client.List(ctx, &list, client.InNamespace(r.Namespace)); err != nil {
		mPassErrors.WithLabelValues("list").Inc()
		return fmt.Errorf("list peers: %w", err)
	}
	var keys map[string][]byte
	keysMsg := ""
	var secret corev1.Secret
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.KeySecret}, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			mPassErrors.WithLabelValues("secret").Inc()
			return fmt.Errorf("get key secret: %w", err)
		}
		keysMsg = fmt.Sprintf("secret %s not found", r.KeySecret)
	} else {
		keys = secret.Data
	}
	managed, err := r.NetDev.ListManaged()
	if err != nil {
		mPassErrors.WithLabelValues("links").Inc()
		return fmt.Errorf("list links: %w", err)
	}
	managedByPeer := map[string]*netdev.State{}
	for i := range managed {
		if name, ok := strings.CutPrefix(managed[i].Name, peer.InterfacePrefix); ok {
			managedByPeer[name] = &managed[i]
		}
	}

	results := map[string]*peerResult{}
	desiredFiles := map[string]string{}
	keepFiles := map[string]bool{}
	ports := map[string]int32{}
	objects := map[string]bool{}
	var errs []error

	// keep leaves whatever exists for this peer as it is.
	keep := func(name string, pr *peerResult) {
		keepFiles[name] = true
		if st := managedByPeer[name]; st != nil {
			ports[name] = int32(st.ListenPort)
		}
	}

	for _, vr := range peer.ValidateSet(list.Items) {
		o := vr.Object
		objects[o.Name] = true
		pr := &peerResult{generation: o.Generation, asn: o.Spec.ASN, iface: peer.InterfacePrefix + o.Name}
		results[o.Name] = pr
		if vr.Err != nil {
			pr.validReason, pr.validMsg = vr.Err.Reason, vr.Err.Message
			pr.tunnelReason, pr.tunnelMsg = ReasonInvalid, "peer is not valid; existing link left as is"
			keep(o.Name, pr)
			continue
		}
		p := vr.Peer
		p.ApplyMeasuredLatency(o.Status.MeasuredLatency)
		p.ApplyTransit(verdict(o.Status.Transit))
		pr.valid, pr.validReason = true, peer.ReasonValid
		pr.listenPort = int32(p.ListenPort)
		link := p.Link
		pr.link = &link

		keyName := p.KeyRef
		if keyName == "" {
			keyName = r.SharedKeyName
		}
		raw, ok := keys[keyName]
		if !ok {
			msg := keysMsg
			if msg == "" {
				msg = fmt.Sprintf("key %q not in secret %s", keyName, r.KeySecret)
			}
			pr.tunnelReason, pr.tunnelMsg = ReasonKeyMissing, msg
			keep(o.Name, pr)
			continue
		}
		priv, err := peer.ParsePrivateKey(strings.TrimSpace(string(raw)))
		if err != nil {
			pr.tunnelReason, pr.tunnelMsg = ReasonKeyMissing, fmt.Sprintf("key %q: %v", keyName, err)
			keep(o.Name, pr)
			continue
		}

		pr.publicKey = priv.PublicKey().String()

		spec := &netdev.Spec{
			Name:          p.Interface(),
			VRF:           r.VRF,
			PrivateKey:    priv,
			ListenPort:    p.ListenPort,
			PeerPublicKey: p.PublicKey,
			Address:       netip.PrefixFrom(p.LocalLinkLocal, 64),
			MTU:           p.MTU,
		}
		if p.Endpoint != nil && r.Resolve != nil {
			addr, err := r.Resolve(ctx, p.Endpoint)
			if err != nil {
				log.Info("endpoint not resolved, keeping the current one", "peer", o.Name, "endpoint", p.Endpoint.String(), "error", err.Error())
			} else {
				spec.Endpoint = addr
			}
		}
		// Re-check before every link change: the term may have ended.
		if r.State.Get() != RoleLeader || ctx.Err() != nil {
			return errNotLeader
		}
		plan, err := r.NetDev.Ensure(spec, now)
		switch {
		case errors.Is(err, netdev.ErrNotManaged):
			pr.tunnelReason, pr.tunnelMsg = ReasonInterfaceConflict,
				fmt.Sprintf("%s exists without alias %q; it is left alone", spec.Name, netdev.Alias)
			keepFiles[o.Name] = true
			continue
		case errors.Is(err, netdev.ErrVRFMissing):
			pr.tunnelReason, pr.tunnelMsg = ReasonVRFMissing, err.Error()
			keep(o.Name, pr)
			continue
		case err != nil:
			pr.tunnelReason, pr.tunnelMsg = ReasonLinkError, err.Error()
			keep(o.Name, pr)
			errs = append(errs, err)
			continue
		}
		if !plan.Empty() {
			mLinkChanges.WithLabelValues("update").Inc()
			log.Info("link changed", "link", spec.Name, "changes", plan.Description)
		}
		pr.tunnelConfigured = true
		ports[o.Name] = pr.listenPort

		content, err := r.Renderer.Render(p)
		if err != nil {
			pr.valid, pr.validReason, pr.validMsg = false, peer.ReasonInvalidSpec, err.Error()
			keepFiles[o.Name] = true
			continue
		}
		desiredFiles[o.Name] = content
	}

	// Cleanup: managed links whose object is gone. Never links without the
	// alias (ListManaged only returns ours).
	var orphans []string
	for name, st := range managedByPeer {
		if !objects[name] {
			orphans = append(orphans, st.Name)
		}
	}
	// Managed links that don't follow the wg-<name> scheme are orphans too.
	for i := range managed {
		if !strings.HasPrefix(managed[i].Name, peer.InterfacePrefix) {
			orphans = append(orphans, managed[i].Name)
		}
	}
	sort.Strings(orphans)
	mDeletionsBlocked.Set(0)
	if len(orphans) > 0 {
		if r.massDeletion(len(orphans), len(managed)) && !r.deletionConfirmed(ctx, len(orphans)) {
			mDeletionsBlocked.Set(float64(len(orphans)))
			log.Error(nil, "refusing to delete many links at once; confirm by setting the control ConfigMap",
				"links", orphans, "managed", len(managed), "configMap", r.ControlConfigMap, "key", ConfirmDeletionsKey, "value", len(orphans))
			for _, n := range orphans {
				name := strings.TrimPrefix(n, peer.InterfacePrefix)
				keepFiles[name] = true
				if st := managedByPeer[name]; st != nil {
					ports[name] = int32(st.ListenPort)
				}
			}
		} else {
			for _, n := range orphans {
				if err := r.NetDev.Delete(n); err != nil {
					errs = append(errs, err)
					continue
				}
				mLinkChanges.WithLabelValues("delete").Inc()
				log.Info("removed link without peer", "link", n)
			}
		}
	}

	// BIRD: only reloads after configure check accepts the files.
	sres, err := r.Dir.Sync(ctx, desiredFiles, keepFiles)
	if err != nil {
		mBirdUp.Set(b2f(bird.IsRejected(err)))
		mPassErrors.WithLabelValues("bird").Inc()
		errs = append(errs, fmt.Errorf("bird: %w", err))
	} else {
		mBirdUp.Set(1)
		for name, rerr := range sres.Rejected {
			if pr := results[name]; pr != nil {
				pr.valid, pr.validReason, pr.validMsg = false, peer.ReasonBIRDRejected, rerr.Error()
			}
			log.Error(rerr, "bird rejected peer config, kept the old one", "peer", name)
		}
		if sres.ConfigChanged {
			log.Info("bird.conf changed, bird reconfigured")
		}
		if sres.ConfigRejected != nil {
			mPassErrors.WithLabelValues("bird-config").Inc()
			errs = append(errs, sres.ConfigRejected)
		}
		if len(sres.Written)+len(sres.Deleted) > 0 {
			log.Info("bird reconfigured", "written", sres.Written, "deleted", sres.Deleted)
		}
	}

	if r.EndpointService != "" {
		if err := r.applyServicePorts(ctx, ports); err != nil {
			mPassErrors.WithLabelValues("service").Inc()
			errs = append(errs, fmt.Errorf("service: %w", err))
		}
	}

	r.results = results
	return errors.Join(errs...)
}

// massDeletion: more than one link and more than MaxDeleteFraction of them.
func (r *Reconciler) massDeletion(n, total int) bool {
	return n > 1 && float64(n) > r.MaxDeleteFraction*float64(total)
}

func (r *Reconciler) deletionConfirmed(ctx context.Context, n int) bool {
	if r.ControlConfigMap == "" {
		return false
	}
	var cm corev1.ConfigMap
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.ControlConfigMap}, &cm); err != nil {
		return false
	}
	return cm.Data[ConfirmDeletionsKey] == strconv.Itoa(n)
}

// applyServicePorts sets spec.ports of the endpoint Service with
// server-side apply, so the operator owns only its port entries. It never
// creates the Service, and leaves it alone when there are no ports (a
// Service needs at least one).
func (r *Reconciler) applyServicePorts(ctx context.Context, ports map[string]int32) error {
	if len(ports) == 0 {
		return nil
	}
	var svc corev1.Service
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.EndpointService}, &svc); err != nil {
		return err
	}
	names := make([]string, 0, len(ports))
	for n := range ports {
		names = append(names, n)
	}
	sort.Strings(names)
	spec := corev1ac.ServiceSpec()
	for _, n := range names {
		p := ports[n]
		spec.WithPorts(corev1ac.ServicePort().
			WithName(peer.InterfacePrefix + n).
			WithProtocol(corev1.ProtocolUDP).
			WithPort(p).
			WithTargetPort(intstr.FromInt32(p)))
	}
	ac := corev1ac.Service(r.EndpointService, r.Namespace).WithSpec(spec)
	return r.Client.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// DefaultResolver resolves hostnames to IPv6 (AAAA) only: the router is IPv6 only.
func DefaultResolver(ctx context.Context, ep *peer.Endpoint) (*net.UDPAddr, error) {
	if a, err := netip.ParseAddr(ep.Host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(ep.Port))), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", ep.Host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no IPv6 address", ep.Host)
	}
	// The same rule as for a configured address: a name can't point the
	// router at itself either.
	if err := peer.CheckEndpointAddr(addrs[0]); err != nil {
		return nil, fmt.Errorf("%s resolves to %s: %w", ep.Host, addrs[0], err)
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], uint16(ep.Port))), nil
}
