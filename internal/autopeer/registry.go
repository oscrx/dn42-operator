package autopeer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

var autNumRe = regexp.MustCompile(`^AS([0-9]{1,10})$`)

// Registry maps mntners to the ASNs they maintain, from a clone of the DN42
// registry (data/aut-num/AS*, "mnt-by:" lines).
type Registry struct {
	Path string

	mu       sync.RWMutex
	byMntner map[string][]int64
	asns     map[int64]bool
	loaded   time.Time
}

// Load (re)reads data/aut-num.
func (r *Registry) Load() error {
	dir := filepath.Join(r.Path, "data", "aut-num")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	byMntner := map[string][]int64{}
	asns := map[int64]bool{}
	for _, e := range ents {
		m := autNumRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		asn, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		mnts, err := readMntBy(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		asns[asn] = true
		for _, mnt := range mnts {
			byMntner[mnt] = append(byMntner[mnt], asn)
		}
	}
	for k := range byMntner {
		sort.Slice(byMntner[k], func(i, j int) bool { return byMntner[k][i] < byMntner[k][j] })
	}
	r.mu.Lock()
	r.byMntner, r.asns, r.loaded = byMntner, asns, time.Now()
	r.mu.Unlock()
	return nil
}

func readMntBy(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == "mnt-by" {
			if v = strings.ToUpper(strings.TrimSpace(v)); v != "" {
				out = append(out, v)
			}
		}
	}
	return out, sc.Err()
}

// ASNsFor returns the ASNs maintained by a mntner (case-insensitive).
func (r *Registry) ASNsFor(mntner string) []int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]int64(nil), r.byMntner[strings.ToUpper(strings.TrimSpace(mntner))]...)
}

// Exists reports whether an aut-num object exists for asn.
func (r *Registry) Exists(asn int64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.asns[asn]
}

// Run reloads (after a git pull if pull is set) every interval until ctx
// is done.
func (r *Registry) Run(ctx context.Context, every time.Duration, pull bool) {
	if every <= 0 {
		return
	}
	log := ctrl.Log.WithName("registry")
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if pull {
			cmd := exec.CommandContext(ctx, "git", "-C", r.Path, "pull", "--ff-only", "--quiet")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Error(err, "git pull", "output", string(out))
			}
		}
		if err := r.Load(); err != nil {
			log.Error(err, "reload")
		}
	}
}
