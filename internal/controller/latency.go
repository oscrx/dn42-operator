package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/latency"
	"github.com/oscrx/dn42-operator/internal/peer"
)

var mPeerRTT = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "dn42_peer_endpoint_rtt_seconds", Help: "Median RTT to the peer's endpoint from the last latency measurement."},
	[]string{"peer", "asn"})

func init() { metrics.Registry.MustRegister(mPeerRTT) }

// LatencyProber measures the endpoint RTT of peers without spec.link once
// per MaxAge (a day) on the leader, writes it to status and triggers a pass
// so the BIRD snippet uses it.
type LatencyProber struct {
	R      *Reconciler
	Pinger latency.Pinger

	Every    time.Duration // how often to look for peers due (default 10m)
	MaxAge   time.Duration // re-measure after this (default 24h)
	Retry    time.Duration // after a failed attempt (default 1h)
	Count    int           // pings per measurement (default 10)
	Interval time.Duration // between pings (default 1s)

	mu       sync.Mutex
	attempts map[string]time.Time
}

// NeedLeaderElection: runs everywhere, measures only as leader.
func (p *LatencyProber) NeedLeaderElection() bool { return false }

func (p *LatencyProber) defaults() {
	if p.Every == 0 {
		p.Every = 10 * time.Minute
	}
	if p.MaxAge == 0 {
		p.MaxAge = 24 * time.Hour
	}
	if p.Retry == 0 {
		p.Retry = time.Hour
	}
	if p.Count == 0 {
		p.Count = 10
	}
	if p.Interval == 0 {
		p.Interval = time.Second
	}
}

// Start runs the loop.
func (p *LatencyProber) Start(ctx context.Context) error {
	p.defaults()
	t := time.NewTicker(p.Every)
	defer t.Stop()
	for {
		if p.R.State.Get() == RoleLeader {
			if n, err := p.Run(ctx); err != nil {
				ctrl.Log.WithName("latency").Error(err, "latency run")
			} else if n > 0 {
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

// Due reports whether a peer needs a measurement now.
func (p *LatencyProber) Due(o *dn42v1.DN42Peer, now time.Time) bool {
	p.defaults()
	if o.Spec.Link != nil || o.Spec.Endpoint == "" {
		return false
	}
	p.mu.Lock()
	last, tried := p.attempts[o.Name]
	p.mu.Unlock()
	if tried && now.Sub(last) < p.Retry {
		return false
	}
	at := o.Status.LatencyMeasuredAt
	return o.Status.MeasuredLatency == nil || at == nil || now.Sub(at.Time) >= p.MaxAge
}

// Run measures every due peer, one after another, and returns how many
// measurements were written.
func (p *LatencyProber) Run(ctx context.Context) (int, error) {
	p.defaults()
	log := ctrl.Log.WithName("latency")
	var list dn42v1.DN42PeerList
	if err := p.R.Client.List(ctx, &list, client.InNamespace(p.R.Namespace)); err != nil {
		return 0, err
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	written := 0
	for i := range list.Items {
		o := &list.Items[i]
		now := p.R.now()
		if !p.Due(o, now) {
			continue
		}
		pp, verr := peer.FromObject(o)
		if verr != nil || pp.Endpoint == nil {
			continue
		}
		p.mu.Lock()
		if p.attempts == nil {
			p.attempts = map[string]time.Time{}
		}
		p.attempts[o.Name] = now
		p.mu.Unlock()

		addr, err := p.R.Resolve(ctx, pp.Endpoint)
		if err != nil {
			log.Info("cannot resolve endpoint for latency", "peer", o.Name, "error", err.Error())
			continue
		}
		ip, _ := netip.AddrFromSlice(addr.IP)
		rtt, lat, err := latency.Measure(ctx, p.Pinger, ip.Unmap(), p.Count, p.Interval)
		if err != nil {
			log.Info("latency measurement failed, keeping the previous value", "peer", o.Name, "endpoint", ip.String(), "error", err.Error())
			continue
		}
		patch := client.MergeFrom(o.DeepCopy())
		o.Status.MeasuredLatency = &lat
		o.Status.MeasuredRTT = &metav1.Duration{Duration: rtt.Round(10 * time.Microsecond)}
		t := metav1.NewTime(p.R.now())
		o.Status.LatencyMeasuredAt = &t
		if err := p.R.Client.Status().Patch(ctx, o, patch); err != nil {
			return written, fmt.Errorf("status of %s: %w", o.Name, err)
		}
		mPeerRTT.WithLabelValues(o.Name, strconv.FormatInt(o.Spec.ASN, 10)).Set(rtt.Seconds())
		log.Info("measured latency", "peer", o.Name, "rtt", rtt.String(), "community", lat)
		written++
	}
	return written, nil
}
