package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types reported in DN42PeerStatus.Conditions.
const (
	// ConditionValid is False when the peer fails a check the schema can't do
	// (duplicate port, duplicate ASN+neighbor, no listen port for a non-4242
	// ASN, BIRD rejecting the rendered config). An invalid peer is skipped:
	// whatever was already built for it is left as it was.
	ConditionValid = "Valid"
	// ConditionTunnelReady is True when the WireGuard link is configured and
	// had a handshake recently.
	ConditionTunnelReady = "TunnelReady"
	// ConditionSessionEstablished is True when BIRD reports the BGP session
	// as Established.
	ConditionSessionEstablished = "SessionEstablished"
)

// LinkValues are the DN42 link communities of the tunnel
// (https://dn42.eu/howto/BGP-communities). They feed the dn42_import and
// dn42_export filter functions in bird.conf.
type LinkValues struct {
	// Latency community, 1 (<2.7ms) .. 9 (>2981ms).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=9
	Latency int32 `json:"latency"`
	// Bandwidth community, 21 (>=0.1 Mbit/s) .. 25 (>=1000 Mbit/s).
	// +kubebuilder:validation:Minimum=21
	// +kubebuilder:validation:Maximum=25
	Bandwidth int32 `json:"bandwidth"`
	// Crypto community, 31 (none) .. 34 (encrypted with PFS; WireGuard).
	// +kubebuilder:validation:Minimum=31
	// +kubebuilder:validation:Maximum=34
	Crypto int32 `json:"crypto"`
}

// DN42PeerSpec is one peer: one WireGuard link wg-<name> and one BGP session.
//
// +kubebuilder:validation:XValidation:rule="!has(self.localLinkLocal) || self.localLinkLocal != self.neighbor",message="localLinkLocal and neighbor must differ"
type DN42PeerSpec struct {
	// ASN of the peer: DN42 (4242420000-4242429999), other networks in the
	// registry (4201000000-4201999999), private (64512-65534) or 76100-76199.
	// +kubebuilder:validation:XValidation:rule="(self >= 4242420000 && self <= 4242429999) || (self >= 4201000000 && self <= 4201999999) || (self >= 64512 && self <= 65534) || (self >= 76100 && self <= 76199)",message="asn must be in a DN42 range"
	ASN int64 `json:"asn"`

	// ListenPort is our UDP port for this tunnel. Default for 424242xxxx
	// ASNs: 2 followed by the last 4 digits of the ASN. Required for other
	// ASNs.
	// +optional
	// +kubebuilder:validation:Minimum=20000
	// +kubebuilder:validation:Maximum=29999
	ListenPort *int32 `json:"listenPort,omitempty"`

	// Endpoint of the peer, "host:port" or "[v6]:port". Optional: without
	// it we only answer.
	// +optional
	// +kubebuilder:validation:MaxLength=261
	// +kubebuilder:validation:Pattern=`^(\[[0-9a-fA-F:.]+\]|[0-9.]+|[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?):[0-9]{1,5}$`
	Endpoint string `json:"endpoint,omitempty"`

	// PublicKey is the peer's WireGuard public key (base64, 32 bytes).
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$`
	PublicKey string `json:"publicKey"`

	// LocalLinkLocal is our address on the link. Default fe80::3818.
	// +optional
	// +kubebuilder:validation:MaxLength=39
	// +kubebuilder:validation:Pattern=`^[fF][eE][89aAbB][0-9a-fA-F]:[0-9a-fA-F:]*$`
	LocalLinkLocal string `json:"localLinkLocal,omitempty"`

	// Neighbor is the peer's link-local address, the BGP neighbor.
	// +kubebuilder:validation:MaxLength=39
	// +kubebuilder:validation:Pattern=`^[fF][eE][89aAbB][0-9a-fA-F]:[0-9a-fA-F:]*$`
	Neighbor string `json:"neighbor"`

	// MTU of the WireGuard link. Default 1420; lower it when the path to the
	// peer has extra encapsulation (e.g. 1380 behind a 6in4 tunnel).
	// +optional
	// +kubebuilder:validation:Minimum=1280
	// +kubebuilder:validation:Maximum=1500
	MTU *int32 `json:"mtu,omitempty"`

	// Link values for the BGP communities. Optional; without them the
	// latency is measured (status.measuredLatency) and bandwidth and crypto
	// use the operator's defaults.
	// +optional
	Link *LinkValues `json:"link,omitempty"`

	// KeyRef is the key in the operator's key Secret holding our private
	// key for this tunnel. Without it the shared autopeer key is used.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	KeyRef string `json:"keyRef,omitempty"`
}

// DN42PeerStatus is written by the leading operator only.
type DN42PeerStatus struct {
	// ObservedGeneration is the generation the status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Interface is the WireGuard link, wg-<name>.
	// +optional
	Interface string `json:"interface,omitempty"`

	// ListenPort is the effective listen port.
	// +optional
	ListenPort int32 `json:"listenPort,omitempty"`

	// Link is the effective link values rendered into BIRD.
	// +optional
	Link *LinkValues `json:"link,omitempty"`

	// LastHandshake is the last WireGuard handshake.
	// +optional
	LastHandshake *metav1.Time `json:"lastHandshake,omitempty"`

	// BGPState is the BGP state BIRD reports (Established, Active, ...).
	// +optional
	BGPState string `json:"bgpState,omitempty"`

	// RoutesImported is the number of routes imported from this peer.
	// +optional
	RoutesImported *int64 `json:"routesImported,omitempty"`

	// MeasuredLatency is the DN42 latency community (1..9) from the median
	// RTT of 10 pings to the endpoint, measured daily when spec.link is not
	// set. It replaces the default latency in the BIRD import/export calls.
	// +optional
	MeasuredLatency *int32 `json:"measuredLatency,omitempty"`

	// MeasuredRTT is the median RTT behind MeasuredLatency.
	// +optional
	MeasuredRTT *metav1.Duration `json:"measuredRTT,omitempty"`

	// LatencyMeasuredAt is when MeasuredLatency was measured.
	// +optional
	LatencyMeasuredAt *metav1.Time `json:"latencyMeasuredAt,omitempty"`
}

// DN42Peer is a DN42 peering: a WireGuard tunnel and a BGP session in BIRD.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dnp,categories=dn42
// +kubebuilder:printcolumn:name="ASN",type=integer,JSONPath=`.spec.asn`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.status.listenPort`
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=`.status.conditions[?(@.type=="Valid")].status`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.bgpState`
// +kubebuilder:printcolumn:name="Handshake",type=date,JSONPath=`.status.lastHandshake`
// +kubebuilder:printcolumn:name="Routes",type=integer,JSONPath=`.status.routesImported`
// +kubebuilder:printcolumn:name="Latency",type=integer,JSONPath=`.status.link.latency`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z][a-z0-9]{0,11}$')",message="name must match ^[a-z][a-z0-9]{0,11}$ (wg-<name> must fit in 15 characters)"
type DN42Peer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DN42PeerSpec   `json:"spec"`
	Status DN42PeerStatus `json:"status,omitempty"`
}

// DN42PeerList is a list of DN42Peer.
//
// +kubebuilder:object:root=true
type DN42PeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DN42Peer `json:"items"`
}
