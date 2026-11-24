package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/netdev"
	"github.com/oscrx/dn42-operator/internal/peer"
)

// StatusLoop writes the peers' status and metrics every Interval and after
// every pass. Only the leader writes.
type StatusLoop struct {
	R        *Reconciler
	Interval time.Duration
}

// NeedLeaderElection is false: the loop runs everywhere and checks the role itself.
func (s *StatusLoop) NeedLeaderElection() bool { return false }

// Start runs the loop.
func (s *StatusLoop) Start(ctx context.Context) error {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-s.R.StatusNow:
		}
		if err := s.R.UpdateStatus(ctx); err != nil {
			ctrl.Log.WithName("status").Error(err, "status update")
		}
	}
}

// UpdateStatus writes the status of every peer seen in the last pass.
func (r *Reconciler) UpdateStatus(ctx context.Context) error {
	if r.State.Get() != RoleLeader {
		resetPeerMetrics()
		return nil
	}
	r.mu.Lock()
	results := make(map[string]peerResult, len(r.results))
	for k, v := range r.results {
		results[k] = *v
	}
	r.mu.Unlock()

	protos, birdErr := r.Bird.ShowProtocols(ctx)
	mBirdUp.Set(b2f(birdErr == nil))
	now := r.now()
	resetPeerMetrics()

	var firstErr error
	for name := range results {
		pr := results[name]
		var obj dn42v1.DN42Peer
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: name}, &obj); err != nil {
			continue // deleted since the pass
		}
		var st *netdev.State
		if pr.tunnelConfigured {
			st, _ = r.NetDev.Inspect(pr.iface)
		}
		var proto *bird.ProtocolStatus
		if birdErr == nil {
			if p, ok := protos[peer.ProtocolPrefix+name]; ok {
				proto = &p
			}
		}
		status := buildStatus(&obj, &pr, st, proto, birdErr, now)

		labels := []string{name, strconv.FormatInt(pr.asn, 10)}
		mPeerValid.WithLabelValues(labels...).Set(b2f(pr.valid))
		mPeerTunnelReady.WithLabelValues(labels...).Set(b2f(condTrue(status.Conditions, dn42v1.ConditionTunnelReady)))
		mPeerEstablished.WithLabelValues(labels...).Set(b2f(status.BGPState == "Established"))
		if status.LastHandshake != nil {
			mPeerHandshakeAge.WithLabelValues(labels...).Set(now.Sub(status.LastHandshake.Time).Seconds())
		}
		if status.RoutesImported != nil {
			mPeerRoutes.WithLabelValues(labels...).Set(float64(*status.RoutesImported))
		}
		if h := verdict(status.Transit); h != nil {
			mPeerTransitHealthy.WithLabelValues(labels...).Set(b2f(*h))
		}

		if equality.Semantic.DeepEqual(obj.Status, status) {
			continue
		}
		patch := client.MergeFrom(obj.DeepCopy())
		obj.Status = status
		if err := r.Client.Status().Patch(ctx, &obj, patch); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("status of %s: %w", name, err)
		}
	}
	return firstErr
}

func buildStatus(obj *dn42v1.DN42Peer, pr *peerResult, st *netdev.State, proto *bird.ProtocolStatus, birdErr error, now time.Time) dn42v1.DN42PeerStatus {
	s := *obj.Status.DeepCopy()
	s.ObservedGeneration = pr.generation
	s.Interface = pr.iface
	s.ListenPort = pr.listenPort
	s.PublicKey = pr.publicKey
	s.Link = pr.link
	gen := pr.generation

	set := func(t string, ok bool, reason, msg string) {
		st := metav1.ConditionFalse
		if ok {
			st = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&s.Conditions, metav1.Condition{
			Type: t, Status: st, Reason: reason, Message: msg, ObservedGeneration: gen,
			LastTransitionTime: metav1.NewTime(now),
		})
	}

	set(dn42v1.ConditionValid, pr.valid, pr.validReason, pr.validMsg)

	switch {
	case pr.tunnelConfigured && st != nil:
		hs := st.LastHandshake()
		if hs.IsZero() {
			s.LastHandshake = nil
		} else {
			t := metav1.NewTime(hs.Truncate(time.Second))
			s.LastHandshake = &t
		}
		if !hs.IsZero() && now.Sub(hs) < netdev.HandshakeFresh {
			set(dn42v1.ConditionTunnelReady, true, ReasonHandshake, "")
		} else {
			set(dn42v1.ConditionTunnelReady, false, ReasonNoHandshake,
				fmt.Sprintf("no handshake in the last %s", netdev.HandshakeFresh))
		}
	case pr.tunnelConfigured:
		set(dn42v1.ConditionTunnelReady, false, ReasonLinkError, "link not found after configuring it")
	default:
		set(dn42v1.ConditionTunnelReady, false, pr.tunnelReason, pr.tunnelMsg)
	}

	switch {
	case birdErr != nil:
		set(dn42v1.ConditionSessionEstablished, false, "BIRDUnavailable", birdErr.Error())
	case proto == nil:
		s.BGPState = ""
		s.RoutesImported = nil
		set(dn42v1.ConditionSessionEstablished, false, "NotConfigured", "no BIRD protocol "+peer.ProtocolPrefix+obj.Name)
	default:
		s.BGPState = proto.BGPState
		if s.BGPState == "" {
			s.BGPState = proto.State
		}
		if proto.HasRoutes {
			n := proto.RoutesImported
			s.RoutesImported = &n
		} else {
			s.RoutesImported = nil
		}
		est := proto.BGPState == "Established"
		reason := s.BGPState
		if reason == "" {
			reason = "Unknown"
		}
		set(dn42v1.ConditionSessionEstablished, est, reason, "")
	}
	setTransitCondition(&s, gen, now)
	return s
}

// setTransitCondition mirrors status.transit (written by the
// TransitProber) as the TransitHealthy condition. The condition is derived
// here so the status loop stays the only writer of the conditions.
func setTransitCondition(s *dn42v1.DN42PeerStatus, gen int64, now time.Time) {
	t := s.Transit
	if t == nil {
		meta.RemoveStatusCondition(&s.Conditions, dn42v1.ConditionTransitHealthy)
		return
	}
	c := metav1.Condition{Type: dn42v1.ConditionTransitHealthy, Status: metav1.ConditionUnknown,
		Reason: "Probing", Message: t.Message, ObservedGeneration: gen, LastTransitionTime: metav1.NewTime(now)}
	if t.Healthy != nil {
		c.Status, c.Reason = metav1.ConditionFalse, dn42v1.TransitBroken
		if *t.Healthy {
			c.Status, c.Reason = metav1.ConditionTrue, dn42v1.TransitHealthy
		}
		switch {
		case t.LastResult == dn42v1.TransitInconclusive:
			c.Reason = dn42v1.TransitInconclusive
		case pending(t):
			c.Reason = "Confirming"
		}
	}
	meta.SetStatusCondition(&s.Conditions, c)
}
