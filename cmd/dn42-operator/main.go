// Command dn42-operator turns DN42Peer objects into WireGuard links and BIRD
// sessions on the node it runs on.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/bird"
	ourctrl "github.com/oscrx/dn42-operator/internal/controller"
	"github.com/oscrx/dn42-operator/internal/netdev"
)

func main() {
	var (
		namespace       = flag.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the DN42Peer objects, key Secret, Service and Lease")
		identity        = flag.String("identity", os.Getenv("NODE_NAME"), "leader election identity (use the node name)")
		leaseName       = flag.String("lease", "dn42-operator", "Lease name")
		keySecret       = flag.String("key-secret", "dn42-wireguard-keys", "Secret with the WireGuard private keys")
		sharedKey       = flag.String("shared-key", "autopeer", "key in the Secret for peers without keyRef")
		vrf             = flag.String("vrf", "vrf-dn42", "VRF the links go into (must exist)")
		birdSocket      = flag.String("bird-socket", "/run/bird/bird.ctl", "BIRD control socket")
		peersDir        = flag.String("peers-dir", "/etc/bird/peers", "directory bird.conf includes peer snippets from")
		birdTemplate    = flag.String("bird-template", "dnpeers", "BIRD bgp template the peers use")
		service         = flag.String("endpoint-service", "", "Service whose spec.ports the operator sets (empty: none)")
		controlCM       = flag.String("control-configmap", "dn42-operator-control", "ConfigMap to confirm a blocked mass deletion (empty: none)")
		maxDeleteFrac   = flag.Float64("max-delete-fraction", 0.5, "refuse a pass that would delete more than this share of the managed links")
		metricsAddr     = flag.String("metrics-bind-address", ":9842", "metrics address (host network: pick a free port)")
		probeAddr       = flag.String("health-probe-bind-address", ":9843", "health probe address")
		cleanupShutdown = flag.Bool("cleanup-on-shutdown", true, "remove managed links before releasing the lease on shutdown")
		podName         = flag.String("pod-name", os.Getenv("POD_NAME"), "own pod name, for the leader label (empty: no label)")
		leaderLabel     = flag.String("leader-label", ourctrl.DefaultLeaderLabel, "pod label the endpoint Service selects the leader by")
		statusInterval  = flag.Duration("status-interval", 30*time.Second, "status and metrics interval")
	)
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	if err := run(runConfig{
		namespace: *namespace, identity: *identity, leaseName: *leaseName,
		keySecret: *keySecret, sharedKey: *sharedKey, vrf: *vrf,
		birdSocket: *birdSocket, peersDir: *peersDir, birdTemplate: *birdTemplate,
		service: *service, controlCM: *controlCM, maxDeleteFrac: *maxDeleteFrac,
		metricsAddr: *metricsAddr, probeAddr: *probeAddr,
		cleanupShutdown: *cleanupShutdown, statusInterval: *statusInterval,
		podName: *podName, leaderLabel: *leaderLabel,
	}); err != nil {
		log.Error(err, "exiting")
		os.Exit(1)
	}
}

type runConfig struct {
	namespace, identity, leaseName, keySecret, sharedKey, vrf string
	birdSocket, peersDir, birdTemplate, service, controlCM    string
	maxDeleteFrac                                             float64
	metricsAddr, probeAddr                                    string
	cleanupShutdown                                           bool
	statusInterval                                            time.Duration
	podName, leaderLabel                                      string
}

func run(c runConfig) error {
	if c.namespace == "" || c.identity == "" {
		return errors.New("--namespace and --identity are required (or POD_NAMESPACE and NODE_NAME)")
	}
	if !bird.ValidIdentifier(c.birdTemplate) {
		return fmt.Errorf("--bird-template %q is not a plain identifier", c.birdTemplate)
	}
	if fi, err := os.Stat(c.peersDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("--peers-dir %s is not a directory", c.peersDir)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := dn42v1.AddToScheme(scheme); err != nil {
		return err
	}

	cfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: c.metricsAddr},
		HealthProbeBindAddress: c.probeAddr,
		// Leader election is our own Elector: followers must keep running
		// to tear down, which the manager's built-in election doesn't do.
		LeaderElection: false,
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{c.namespace: {}},
			ByObject: map[client.Object]cache.ByObject{
				// Only the one key Secret, so RBAC can be limited to it.
				&corev1.Secret{}: {Field: fields.OneTermEqualSelector("metadata.name", c.keySecret)},
			},
		},
	})
	if err != nil {
		return err
	}

	var labeler *ourctrl.PodLabeler
	if c.podName != "" {
		labeler = &ourctrl.PodLabeler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(),
			Namespace: c.namespace, PodName: c.podName, Label: c.leaderLabel}
	}
	birdClient := &bird.Client{Socket: c.birdSocket, Timeout: 10 * time.Second}
	state := &ourctrl.RoleState{}
	r := &ourctrl.Reconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Namespace:         c.namespace,
		KeySecret:         c.keySecret,
		SharedKeyName:     c.sharedKey,
		VRF:               c.vrf,
		EndpointService:   c.service,
		ControlConfigMap:  c.controlCM,
		MaxDeleteFraction: c.maxDeleteFrac,
		NetDev:            netdev.NewLinux(),
		Dir:               &bird.Dir{Path: c.peersDir, Bird: birdClient},
		Bird:              birdClient,
		Renderer:          bird.Renderer{Template: c.birdTemplate},
		Resolve:           ourctrl.DefaultResolver,
		State:             state,
		Labeler:           labeler,
		Events:            make(chan struct{}, 1),
		StatusNow:         make(chan struct{}, 1),
	}

	all := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: c.namespace, Name: "all"}}}
	})
	generic := make(chan event.GenericEvent, 1)
	go func() {
		for range r.Events {
			select {
			case generic <- event.GenericEvent{Object: &dn42v1.DN42Peer{}}:
			default:
			}
		}
	}()
	err = ctrl.NewControllerManagedBy(mgr).
		Named("dn42peer").
		Watches(&dn42v1.DN42Peer{}, all, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Secret{}, all).
		WatchesRawSource(source.Channel(generic, all)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
	if err != nil {
		return err
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	if err := mgr.Add(&ourctrl.Elector{
		Client:            cs.CoordinationV1(),
		Namespace:         c.namespace,
		Name:              c.leaseName,
		Identity:          c.identity,
		LeaseDuration:     15 * time.Second,
		RenewDeadline:     10 * time.Second,
		RetryPeriod:       2 * time.Second,
		State:             state,
		Teardown:          r.Teardown,
		Trigger:           r.Trigger,
		CleanupOnShutdown: c.cleanupShutdown,
	}); err != nil {
		return err
	}
	if err := mgr.Add(&ourctrl.StatusLoop{R: r, Interval: c.statusInterval}); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("leader", func(*http.Request) error { return r.Ready() }); err != nil {
		return err
	}
	return mgr.Start(ctrl.SetupSignalHandler())
}
