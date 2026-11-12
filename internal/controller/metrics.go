package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	mLeader = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dn42_operator_leader", Help: "1 if this replica holds the lease."})
	mPasses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dn42_operator_passes_total", Help: "Reconcile passes."})
	mPassErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dn42_operator_pass_errors_total", Help: "Reconcile passes that stopped early, by stage."}, []string{"stage"})
	mLinkChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dn42_operator_link_changes_total", Help: "Link create/update/delete operations."}, []string{"op"})
	mDeletionsBlocked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dn42_operator_deletions_blocked", Help: "Managed links the last pass refused to delete (mass deletion guard)."})
	mBirdUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dn42_operator_bird_up", Help: "1 if the BIRD control socket answered."})

	mPeerValid = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dn42_peer_valid", Help: "1 if the peer passed validation."}, []string{"peer", "asn"})
	mPeerTunnelReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dn42_peer_tunnel_ready", Help: "1 if the tunnel is configured and had a recent handshake."}, []string{"peer", "asn"})
	mPeerHandshakeAge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dn42_peer_handshake_age_seconds", Help: "Seconds since the last WireGuard handshake."}, []string{"peer", "asn"})
	mPeerEstablished = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dn42_peer_bgp_established", Help: "1 if the BGP session is Established."}, []string{"peer", "asn"})
	mPeerRoutes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dn42_peer_routes_imported", Help: "Routes imported from the peer."}, []string{"peer", "asn"})
)

func init() {
	metrics.Registry.MustRegister(mLeader, mPasses, mPassErrors, mLinkChanges, mDeletionsBlocked, mBirdUp,
		mPeerValid, mPeerTunnelReady, mPeerHandshakeAge, mPeerEstablished, mPeerRoutes)
}

func resetPeerMetrics() {
	for _, g := range []*prometheus.GaugeVec{mPeerValid, mPeerTunnelReady, mPeerHandshakeAge, mPeerEstablished, mPeerRoutes} {
		g.Reset()
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func condTrue(conds []v1.Condition, t string) bool {
	for _, c := range conds {
		if c.Type == t {
			return c.Status == v1.ConditionTrue
		}
	}
	return false
}
