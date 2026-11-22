package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// fakeLock is an in-memory lease. failRenew makes renewals (updates with a
// holder) fail while releases (empty holder) still succeed: the API is slow
// for long enough to lose the lease, then recovers.
type fakeLock struct {
	mu        sync.Mutex
	id        string
	rec       *resourcelock.LeaderElectionRecord
	raw       []byte
	failRenew bool
	events    *[]string
}

func (f *fakeLock) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rec == nil {
		return nil, nil, errNotFound
	}
	r := *f.rec
	return &r, f.raw, nil
}

var errNotFound = apierrors.NewNotFound(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "dn42-operator")

func (f *fakeLock) Create(_ context.Context, r resourcelock.LeaderElectionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec, f.raw = &r, []byte(r.HolderIdentity+r.RenewTime.String())
	return nil
}

func (f *fakeLock) Update(_ context.Context, r resourcelock.LeaderElectionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.HolderIdentity != "" && f.failRenew {
		return errors.New("api timeout")
	}
	if r.HolderIdentity == "" {
		*f.events = append(*f.events, "release")
	}
	f.rec, f.raw = &r, []byte(r.HolderIdentity+r.RenewTime.String())
	return nil
}

func (f *fakeLock) RecordEvent(string) {}
func (f *fakeLock) Identity() string   { return f.id }
func (f *fakeLock) Describe() string   { return "fake" }

type electorRun struct {
	e      *Elector
	lock   *fakeLock
	events *[]string
	mu     *sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func startElector(t *testing.T, teardownOnLoss bool) *electorRun {
	t.Helper()
	events := &[]string{}
	var mu sync.Mutex
	lock := &fakeLock{id: "node-a", events: events}
	state := &RoleState{}
	run := &electorRun{lock: lock, events: events, mu: &mu, done: make(chan struct{})}
	run.e = &Elector{
		Identity: "node-a", Lock: lock, State: state,
		LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 100 * time.Millisecond,
		Teardown: func(context.Context) error {
			lock.mu.Lock()
			*events = append(*events, "teardown")
			lock.mu.Unlock()
			return nil
		},
		CancelPass:          func() {},
		Trigger:             func() {},
		TeardownOnLeaseLoss: teardownOnLoss,
	}
	ctx, cancel := context.WithCancel(context.Background())
	run.cancel = cancel
	go func() {
		_ = run.e.Start(ctx)
		close(run.done)
	}()
	waitRole(t, state, RoleLeader)
	t.Cleanup(func() { cancel(); <-run.done })
	return run
}

func waitRole(t *testing.T, s *RoleState, want Role) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.Get() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("role %s, want %s", s.Get(), want)
}

func (r *electorRun) snapshot() []string {
	r.lock.mu.Lock()
	defer r.lock.mu.Unlock()
	return append([]string(nil), *r.events...)
}

func TestLeaseLossTearsDownBeforeRelease(t *testing.T) {
	run := startElector(t, true)
	run.lock.mu.Lock()
	run.lock.failRenew = true
	run.lock.mu.Unlock()

	waitRole(t, run.e.State, RoleFollower)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(run.snapshot()) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	ev := run.snapshot()
	if len(ev) < 2 || ev[0] != "teardown" || ev[1] != "release" {
		t.Fatalf("events %v: the links must be gone before the lease is released", ev)
	}
}

func TestLeaseLossKeepsTunnelsWhenConfigured(t *testing.T) {
	run := startElector(t, false)
	run.lock.mu.Lock()
	run.lock.failRenew = true
	run.lock.mu.Unlock()

	// Not leader any more, but not tearing down either: Unknown until a
	// holder is seen (here: we take it back once renewals work again).
	waitRole(t, run.e.State, RoleUnknown)
	for _, ev := range run.snapshot() {
		if ev == "teardown" {
			t.Fatalf("tore down on lease loss: %v", run.snapshot())
		}
	}
	run.lock.mu.Lock()
	run.lock.failRenew = false
	run.lock.mu.Unlock()
	waitRole(t, run.e.State, RoleLeader)
}

func TestShutdownWithoutCleanupKeepsTunnels(t *testing.T) {
	run := startElector(t, true) // teardown on loss on, cleanup on shutdown off
	run.cancel()
	<-run.done
	for _, ev := range run.snapshot() {
		if ev == "teardown" {
			t.Fatalf("tore down on shutdown without cleanup: %v", run.snapshot())
		}
	}
	if run.e.State.Get() != RoleStopping {
		t.Errorf("role %s", run.e.State.Get())
	}
}

func TestShutdownWithCleanupTearsDownFirst(t *testing.T) {
	run := startElector(t, true)
	run.e.CleanupOnShutdown = true
	run.cancel()
	<-run.done
	ev := run.snapshot()
	if len(ev) < 2 || ev[0] != "teardown" || ev[1] != "release" {
		t.Fatalf("events %v", ev)
	}
}
