package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DefaultLeaderLabel is set to "true" on the leader's pod and "false" on the
// others. The endpoint Service selects on it, so only the leader receives
// tunnel traffic while every healthy pod can be Ready (a follower that is
// never Ready would stall a DaemonSet rolling update).
const DefaultLeaderLabel = "dn42.oscarr.nl/leader"

// PodLabeler maintains the leader label on this replica's own pod.
type PodLabeler struct {
	Client    client.Client // writes go straight to the API server
	Reader    client.Reader // uncached: pods are not in the cache
	Namespace string
	PodName   string
	Label     string

	mu        sync.Mutex
	confirmed *bool // value the API server last accepted
}

func (l *PodLabeler) patch(ctx context.Context, name string, leader bool) error {
	v := "false"
	if leader {
		v = "true"
	}
	body, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]string{l.Label: v}}})
	if err != nil {
		return err
	}
	pod := &corev1.Pod{}
	pod.Namespace, pod.Name = l.Namespace, name
	return l.Client.Patch(ctx, pod, client.RawPatch(types.MergePatchType, body))
}

// Set writes the label on our own pod. On failure the confirmed value is
// forgotten, so readiness fails until the label is known to match the role.
func (l *PodLabeler) Set(ctx context.Context, leader bool) error {
	err := l.patch(ctx, l.PodName, leader)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.confirmed = nil
		return fmt.Errorf("label own pod %s=%v: %w", l.Label, leader, err)
	}
	l.confirmed = &leader
	return nil
}

// ClearOthers sets the label to false on every other pod that still has it
// true, e.g. the pod of a leader that lost the lease without reaching the API.
func (l *PodLabeler) ClearOthers(ctx context.Context) error {
	var pods corev1.PodList
	if err := l.Reader.List(ctx, &pods, client.InNamespace(l.Namespace), client.MatchingLabels{l.Label: "true"}); err != nil {
		return fmt.Errorf("list leader pods: %w", err)
	}
	var errs []error
	for _, p := range pods.Items {
		if p.Name == l.PodName {
			continue
		}
		if err := l.patch(ctx, p.Name, false); err != nil {
			errs = append(errs, fmt.Errorf("clear leader label on %s: %w", p.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Confirmed returns the label value last accepted by the API server.
func (l *PodLabeler) Confirmed() (leader, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.confirmed == nil {
		return false, false
	}
	return *l.confirmed, true
}
