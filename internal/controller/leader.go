package controller

import (
	"context"
	"sync/atomic"
	"time"

	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Role is what this replica currently is.
type Role int32

const (
	// RoleUnknown means just started: the lease hasn't been seen yet. Nothing is
	// built or removed, so a restarted leader doesn't tear down its own
	// tunnels before it renews the lease.
	RoleUnknown Role = iota
	// RoleLeader builds the tunnels and BIRD config and reports ready.
	RoleLeader
	// RoleFollower removes all managed links and peer configs.
	RoleFollower
	// RoleStopping means shutting down, already torn down. Nothing is changed.
	RoleStopping
)

func (r Role) String() string {
	return [...]string{"unknown", "leader", "follower", "stopping"}[r]
}

// RoleState holds the current role.
type RoleState struct{ v atomic.Int32 }

// Get returns the role.
func (s *RoleState) Get() Role { return Role(s.v.Load()) }

// Set sets the role.
func (s *RoleState) Set(r Role) {
	s.v.Store(int32(r))
	if r == RoleLeader {
		mLeader.Set(1)
	} else {
		mLeader.Set(0)
	}
}

// Elector runs Lease leader election. It always runs (it is not itself
// gated by leader election) and drives the RoleState.
type Elector struct {
	Client    coordinationv1.CoordinationV1Interface
	Namespace string
	Name      string
	// Identity should be the node name, so a restarted pod on the same node
	// takes its own lease back at once.
	Identity string
	// Lock overrides the Lease lock (tests).
	Lock resourcelock.Interface

	LeaseDuration, RenewDeadline, RetryPeriod time.Duration

	State *RoleState
	// Teardown removes all managed links and peer configs.
	Teardown func(ctx context.Context) error
	// CancelPass aborts a reconcile pass in progress, so Teardown doesn't
	// wait behind it.
	CancelPass func()
	// Trigger asks for a reconcile pass.
	Trigger func()
	// CleanupOnShutdown tears down before releasing the lease on shutdown.
	// Needed with a standby (a key must never be live on two nodes); off on a
	// single router, so an operator restart doesn't flap every session.
	CleanupOnShutdown bool
	// TeardownOnLeaseLoss tears down as soon as the lease can't be renewed,
	// before another replica can take it. Needed with a standby. Off on a
	// single router: an API outage then stops all changes but keeps the
	// tunnels up, and links are only removed once another holder is seen.
	TeardownOnLeaseLoss bool
}

// NeedLeaderElection makes the manager run the elector on every replica.
func (e *Elector) NeedLeaderElection() bool { return false }

// releaseGuard wraps the lock so that releasing it (client-go writes an
// empty holder) waits until this replica has stood down. client-go releases
// before it calls OnStoppedLeading; without this, another replica could take
// the lease while our tunnels still run.
type releaseGuard struct {
	resourcelock.Interface
	beforeRelease func()
}

//nolint:gocritic // hugeParam: the signature is resourcelock.Interface's
func (g *releaseGuard) Update(ctx context.Context, rec resourcelock.LeaderElectionRecord) error {
	if rec.HolderIdentity == "" {
		g.beforeRelease()
	}
	return g.Interface.Update(ctx, rec)
}

// lostLease handles the end of our term other than by shutdown. It runs
// before the lease is released (releaseGuard) or, if no release happens,
// from OnStoppedLeading; only the first call does anything.
func (e *Elector) lostLease() {
	if e.State.Get() != RoleLeader {
		return
	}
	log := ctrl.Log.WithName("leader")
	if !e.TeardownOnLeaseLoss {
		// Touch nothing until we know who holds the lease: either we take it
		// back, or another holder appears and we become a follower.
		e.State.Set(RoleUnknown)
		if e.CancelPass != nil {
			e.CancelPass()
		}
		log.Info("lost the lease, keeping the tunnels until another holder is seen")
		return
	}
	e.State.Set(RoleFollower)
	if e.CancelPass != nil {
		e.CancelPass()
	}
	log.Info("lost the lease, removing managed links before it can be taken over")
	tctx, tcancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer tcancel()
	if err := e.Teardown(tctx); err != nil {
		log.Error(err, "teardown after losing the lease")
	}
}

// Start runs the election until ctx is done.
func (e *Elector) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("leader")
	ectx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		wasLeader := e.State.Get() == RoleLeader
		e.State.Set(RoleStopping)
		if wasLeader && e.CleanupOnShutdown {
			if e.CancelPass != nil {
				e.CancelPass()
			}
			tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Second)
			if err := e.Teardown(tctx); err != nil {
				log.Error(err, "teardown on shutdown")
			}
			tcancel()
		}
		// Now release the lease.
		cancel()
	}()

	lock := e.Lock
	if lock == nil {
		lock = &resourcelock.LeaseLock{
			LeaseMeta:  metaFor(e.Namespace, e.Name),
			Client:     e.Client,
			LockConfig: resourcelock.ResourceLockConfig{Identity: e.Identity},
		}
	}
	lock = &releaseGuard{Interface: lock, beforeRelease: e.lostLease}
	for ectx.Err() == nil {
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   e.LeaseDuration,
			RenewDeadline:   e.RenewDeadline,
			RetryPeriod:     e.RetryPeriod,
			ReleaseOnCancel: true,
			Name:            e.Name,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(lctx context.Context) {
					// Runs in its own goroutine: the term may already be over.
					if lctx.Err() != nil || e.State.Get() == RoleStopping {
						return
					}
					log.Info("became leader")
					e.State.Set(RoleLeader)
					e.Trigger()
				},
				OnStoppedLeading: func() {
					if e.State.Get() == RoleStopping {
						return
					}
					e.lostLease()
					e.Trigger()
				},
				OnNewLeader: func(id string) {
					if id == e.Identity || e.State.Get() == RoleStopping {
						return
					}
					log.Info("following", "leader", id)
					if e.State.Get() != RoleLeader {
						e.State.Set(RoleFollower)
						e.Trigger()
					}
				},
			},
		})
		if err != nil {
			return err
		}
		le.Run(ectx)
		select {
		case <-ectx.Done():
		case <-time.After(e.RetryPeriod):
		}
	}
	return nil
}
