package autopeer

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
)

// KubeStatus reads DN42Peer objects (read-only RBAC: get/list dn42peers).
type KubeStatus struct {
	Client    client.Reader
	Namespace string
}

// Peers lists the live objects.
func (k *KubeStatus) Peers(ctx context.Context) ([]dn42v1.DN42Peer, error) {
	var l dn42v1.DN42PeerList
	if err := k.Client.List(ctx, &l, client.InNamespace(k.Namespace)); err != nil {
		return nil, err
	}
	return l.Items, nil
}
