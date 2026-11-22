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

	LeaseDuration, RenewDeadline, RetryPeriod time.Duration

	State *RoleState
	// Teardown removes all managed links and peer configs.
	Teardown func(ctx context.Context) error
	// Trigger asks for a reconcile pass.
	Trigger func()
	// CleanupOnShutdown tears down before releasing the lease on shutdown,
	// so a tunnel key is never live on two nodes.
	CleanupOnShutdown bool
}

// NeedLeaderElection makes the manager run the elector on every replica.
func (e *Elector) NeedLeaderElection() bool { return false }

// Start runs the election until ctx is done.
func (e *Elector) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("leader")
	ectx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		if e.State.Get() == RoleLeader && e.CleanupOnShutdown {
			e.State.Set(RoleStopping)
			tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Second)
			if err := e.Teardown(tctx); err != nil {
				log.Error(err, "teardown on shutdown")
			}
			tcancel()
		} else {
			e.State.Set(RoleStopping)
		}
		// Now release the lease.
		cancel()
	}()

	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metaFor(e.Namespace, e.Name),
		Client:     e.Client,
		LockConfig: resourcelock.ResourceLockConfig{Identity: e.Identity},
	}
	for ectx.Err() == nil {
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   e.LeaseDuration,
			RenewDeadline:   e.RenewDeadline,
			RetryPeriod:     e.RetryPeriod,
			ReleaseOnCancel: true,
			Name:            e.Name,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(context.Context) {
					if e.State.Get() == RoleStopping {
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
					was := e.State.Get()
					e.State.Set(RoleFollower)
					if was == RoleLeader {
						log.Info("lost the lease, removing managed links")
						// Synchronous: the links must be gone before another
						// replica can take the lease.
						tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
						if err := e.Teardown(tctx); err != nil {
							log.Error(err, "teardown after losing the lease")
						}
						tcancel()
					}
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
