// Command autopeer is the DN42 autopeering web app: log in through a DN42
// identity provider, submit a peer, get a PR in the peers repo.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	dn42v1 "github.com/oscrx/dn42-operator/api/v1alpha1"
	"github.com/oscrx/dn42-operator/internal/autopeer"
	"github.com/oscrx/dn42-operator/internal/registry"
)

func main() {
	configPath := flag.String("config", "/etc/autopeer/config.yaml", "config file")
	fakeRepo := flag.Bool("fake-repo", false, "keep PRs in memory instead of calling GitHub (local testing)")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if err := run(*configPath, *fakeRepo); err != nil {
		ctrl.Log.Error(err, "exiting")
		os.Exit(1)
	}
}

func run(configPath string, fakeRepo bool) error {
	cfg, err := autopeer.LoadConfig(configPath)
	if err != nil {
		return err
	}
	key, err := autopeer.ReadKeyFile(cfg.CookieKeyFile)
	if err != nil {
		return fmt.Errorf("cookie key: %w", err)
	}
	cookies, err := autopeer.NewCookies(key, strings.HasPrefix(cfg.PublicURL, "https://"))
	if err != nil {
		return err
	}
	reg := &registry.Registry{Path: cfg.Registry.Path}
	regErr := reg.Load() // the git-sync sidecar may not have cloned yet

	var repo autopeer.PeerRepo
	if fakeRepo {
		repo = &autopeer.FakeRepo{Files: map[string][]byte{}}
	} else {
		gh, err := autopeer.NewGitHubApp(cfg.GitHub)
		if err != nil {
			return fmt.Errorf("github app: %w", err)
		}
		repo = gh
	}

	var status autopeer.StatusSource
	if cfg.Kubernetes.Enabled {
		scheme := runtime.NewScheme()
		if err := dn42v1.AddToScheme(scheme); err != nil {
			return err
		}
		c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
		status = &autopeer.KubeStatus{Client: c, Namespace: cfg.Kubernetes.Namespace}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		for regErr != nil {
			ctrl.Log.Info("registry not loaded yet, mntner logins find no ASNs until it is", "error", regErr.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			regErr = reg.Load()
		}
		reg.Run(ctx, cfg.Registry.Refresh.Duration, cfg.Registry.Pull)
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           autopeer.NewServer(cfg, reg, repo, status, cookies).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	ctrl.Log.Info("listening", "addr", cfg.Listen, "providers", len(cfg.Providers))
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
