package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/netdev"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ns = "dn42"

// harness wires a Reconciler to a fake API server.
type harness struct {
	t      *testing.T
	r      *Reconciler
	c      client.WithWatch
	listOK bool // false: List fails like an API outage
}

func scheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := dn42v1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func genKey(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keySecret(t *testing.T, names ...string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "keys"}, Data: map[string][]byte{}}
	for _, n := range names {
		s.Data[n] = []byte(genKey(t).String() + "\n")
	}
	return s
}

func endpointService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "endpoint"},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Name: "placeholder", Protocol: corev1.ProtocolUDP, Port: 1}}},
	}
}

var created = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func mkPeer(name string, asn int64, port int32, neighbor string, age int) *dn42v1.DN42Peer {
	pub := "08dzv758I5APqJizgw/W6O+FceyHSCbx/L/GZ3TL5TQ="
	p := &dn42v1.DN42Peer{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 1,
			CreationTimestamp: metav1.NewTime(created.Add(time.Duration(age) * time.Hour))},
		Spec: dn42v1.DN42PeerSpec{ASN: asn, PublicKey: pub, Neighbor: neighbor,
			Endpoint: "[2001:db8::1]:51820"},
	}
	if port != 0 {
		p.Spec.ListenPort = &port
	}
	return p
}

func newHarness(t *testing.T, nd netdev.Manager, dir *bird.Dir, bc BirdControl, objs ...client.Object) *harness {
	h := &harness{t: t, listOK: true}
	h.c = fake.NewClientBuilder().
		WithScheme(scheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&dn42v1.DN42Peer{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if !h.listOK {
					return errors.New("connection refused")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()
	state := &RoleState{}
	state.Set(RoleLeader)
	h.r = &Reconciler{
		Client: h.c, APIReader: h.c, Namespace: ns,
		KeySecret: "keys", SharedKeyName: "autopeer", VRF: "vrf-dn42",
		EndpointService: "endpoint", ControlConfigMap: "control", MaxDeleteFraction: 0.5,
		NetDev: nd, Dir: dir, Bird: bc, Renderer: bird.Renderer{Template: "dnpeers"},
		Resolve: DefaultResolver,
		State:   state, Events: make(chan struct{}, 1), StatusNow: make(chan struct{}, 1),
	}
	return h
}

func (h *harness) pass() error {
	h.t.Helper()
	return h.r.Pass(context.Background())
}

func (h *harness) mustPass() {
	h.t.Helper()
	if err := h.pass(); err != nil {
		h.t.Fatalf("pass: %v", err)
	}
}

func (h *harness) peer(name string) *dn42v1.DN42Peer {
	h.t.Helper()
	var p dn42v1.DN42Peer
	if err := h.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &p); err != nil {
		h.t.Fatal(err)
	}
	return &p
}

func (h *harness) cond(name, typ string) *metav1.Condition {
	h.t.Helper()
	for _, c := range h.peer(name).Status.Conditions {
		if c.Type == typ {
			return &c
		}
	}
	h.t.Fatalf("%s has no %s condition", name, typ)
	return nil
}

func (h *harness) servicePorts() map[string]int32 {
	h.t.Helper()
	var svc corev1.Service
	if err := h.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "endpoint"}, &svc); err != nil {
		h.t.Fatal(err)
	}
	out := map[string]int32{}
	for _, p := range svc.Spec.Ports {
		out[p.Name] = p.Port
	}
	return out
}

func (h *harness) create(o client.Object) {
	h.t.Helper()
	if err := h.c.Create(context.Background(), o); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) delete(o client.Object) {
	h.t.Helper()
	if err := h.c.Delete(context.Background(), o); err != nil {
		h.t.Fatal(err)
	}
}
