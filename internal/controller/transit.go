package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/peer"
	"github.com/oscrx/dn42-operator/internal/transit"
)

// RouteChecker reports whether a BIRD protocol has a route covering addr.
type RouteChecker interface {
	HasRoute(ctx context.Context, protocol string, addr netip.Addr) (bool, error)
}

// TransitProber checks, on the leader, whether TCP through each established
// peer works when the replies come back via another peer
// (internal/transit), and keeps the verdict in status.transit. The next
// pass renders it into the peer's dn42_import call when the renderer has
// TransitArg set.
//
// A verdict changes only after two probes in a row agree. Peers are probed
// daily while healthy, hourly while broken or inconclusive, and again after
// Confirm when a probe disagrees with the verdict.
type TransitProber struct {
	R        *Reconciler
	Net      transit.Net
	Routes   RouteChecker
	Targets  []transit.Target
	Timeouts transit.Timeouts

	Every        time.Duration // how often to look for peers due (default 5m)
	Confirm      time.Duration // re-probe a disagreeing result after (default 5m)
	HealthyEvery time.Duration // default 24h
	BrokenEvery  time.Duration // also for inconclusive results (default 1h)

	ready bool // Net.Setup succeeded
}

// NeedLeaderElection is false: runs everywhere, probes only as leader.
func (p *TransitProber) NeedLeaderElection() bool { return false }

func (p *TransitProber) defaults() {
	if p.Every == 0 {
		p.Every = 5 * time.Minute
	}
	if p.Confirm == 0 {
		p.Confirm = 5 * time.Minute
	}
	if p.HealthyEvery == 0 {
		p.HealthyEvery = 24 * time.Hour
	}
	if p.BrokenEvery == 0 {
		p.BrokenEvery = time.Hour
	}
}

// Start runs the loop and removes the steering on exit.
func (p *TransitProber) Start(ctx context.Context) error {
	p.defaults()
	log := ctrl.Log.WithName("transit")
	defer func() {
		if p.ready {
			if err := p.Net.Close(); err != nil {
				log.Error(err, "removing the transit probe's rule and table")
			}
		}
	}()
	t := time.NewTicker(p.Every)
	defer t.Stop()
	for {
		if p.R.State.Get() == RoleLeader {
			if changed, err := p.Run(ctx); err != nil {
				log.Error(err, "transit run")
			} else if changed {
				p.R.Trigger()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Due reports whether a peer needs a probe now. Only peers with an
// established session are probed.
func (p *TransitProber) Due(o *dn42v1.DN42Peer, now time.Time) bool {
	p.defaults()
	if !condTrue(o.Status.Conditions, dn42v1.ConditionValid) || !condTrue(o.Status.Conditions, dn42v1.ConditionSessionEstablished) {
		return false
	}
	st := o.Status.Transit
	if st == nil || st.ProbedAt == nil {
		return true
	}
	age := now.Sub(st.ProbedAt.Time)
	switch {
	case pending(st):
		return age >= p.Confirm
	case st.Healthy != nil && *st.Healthy:
		return age >= p.HealthyEvery
	default:
		return age >= p.BrokenEvery
	}
}

// pending is true when the last probe disagrees with the verdict and needs
// a second one to confirm.
func pending(st *dn42v1.TransitStatus) bool {
	var res bool
	switch st.LastResult {
	case dn42v1.TransitHealthy:
		res = true
	case dn42v1.TransitBroken:
	default:
		return false
	}
	return st.Healthy == nil || *st.Healthy != res
}

// NextTransit is the status after a probe: the verdict follows the result
// only when it matches the previous one.
func NextTransit(prev *dn42v1.TransitStatus, result, message string, now time.Time) *dn42v1.TransitStatus {
	n := &dn42v1.TransitStatus{}
	if prev != nil {
		n = prev.DeepCopy()
	}
	last := n.LastResult
	n.LastResult, n.Message = result, message
	t := metav1.NewTime(now)
	n.ProbedAt = &t
	if result != dn42v1.TransitInconclusive && result == last {
		h := result == dn42v1.TransitHealthy
		n.Healthy = &h
	}
	return n
}

func verdict(st *dn42v1.TransitStatus) *bool {
	if st == nil {
		return nil
	}
	return st.Healthy
}

func sameVerdict(a, b *bool) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// Run probes every due peer, one after another, and reports whether a
// verdict changed.
func (p *TransitProber) Run(ctx context.Context) (bool, error) {
	p.defaults()
	log := ctrl.Log.WithName("transit")
	var list dn42v1.DN42PeerList
	if err := p.R.Client.List(ctx, &list, client.InNamespace(p.R.Namespace)); err != nil {
		return false, err
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	changed := false
	for i := range list.Items {
		o := &list.Items[i]
		if !p.Due(o, p.R.now()) {
			continue
		}
		pp, verr := peer.FromObject(o)
		if verr != nil {
			continue
		}
		if !p.ready {
			if err := p.Net.Setup(); err != nil {
				return changed, err
			}
			p.ready = true
		}
		checks, err := p.probe(ctx, pp)
		if err != nil {
			log.Info("transit probe failed", "peer", o.Name, "error", err.Error())
			continue
		}
		result, msg := transit.Judge(checks)
		next := NextTransit(o.Status.Transit, result, msg, p.R.now())
		if !sameVerdict(verdict(o.Status.Transit), next.Healthy) {
			changed = true
			log.Info("transit verdict changed", "peer", o.Name, "healthy", *next.Healthy, "detail", msg)
		} else {
			log.V(1).Info("transit probed", "peer", o.Name, "result", result, "detail", msg)
		}
		patch := client.MergeFrom(o.DeepCopy())
		o.Status.Transit = next
		if err := p.R.Client.Status().Patch(ctx, o, patch); err != nil {
			return changed, fmt.Errorf("status of %s: %w", o.Name, err)
		}
	}
	return changed, nil
}

// probe tries each target the peer has a route to, forced through the peer
// and over the normal routes.
func (p *TransitProber) probe(ctx context.Context, pp *peer.Peer) ([]transit.Check, error) {
	checks := make([]transit.Check, len(p.Targets))
	var dsts []netip.Addr
	for i, t := range p.Targets {
		checks[i].Target = t
		ok, err := p.Routes.HasRoute(ctx, pp.Protocol(), t.Addr.Addr())
		if err != nil {
			return nil, err
		}
		if !ok {
			checks[i].Via.Outcome = transit.NoRoute
			continue
		}
		dsts = append(dsts, t.Addr.Addr())
	}
	if len(dsts) == 0 {
		return checks, nil
	}
	undo, err := p.Net.Steer(pp.Interface(), pp.Neighbor, dsts)
	if err != nil {
		return nil, err
	}
	defer undo()
	for i := range checks {
		if checks[i].Via.Outcome == transit.NoRoute {
			continue
		}
		checks[i].Control = transit.Try(ctx, p.Net, checks[i].Target, false, p.Timeouts)
		checks[i].Via = transit.Try(ctx, p.Net, checks[i].Target, true, p.Timeouts)
	}
	return checks, nil
}
