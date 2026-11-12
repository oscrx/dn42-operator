package bird

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oscrx/dn42-operator/internal/peer"
)

// Controller is the part of the BIRD client the peers directory needs.
type Controller interface {
	ConfigureCheck(ctx context.Context) error
	Configure(ctx context.Context) error
}

// Dir manages the peers directory that bird.conf includes
// (include "/etc/bird/peers/*.conf";). Only files named <peer>.conf with a
// valid peer name are touched.
type Dir struct {
	Path string
	Bird Controller

	configured bool // a configure succeeded since start
}

// SyncResult reports what Sync did.
type SyncResult struct {
	// Rejected holds the peers whose new snippet BIRD refused; their old
	// file (or none) was kept.
	Rejected map[string]error
	Written  []string
	Deleted  []string
	// Reloaded is true when "configure" ran.
	Reloaded bool
}

// Read returns the managed files by peer name.
func (d *Dir) Read() (map[string]string, error) {
	ents, err := os.ReadDir(d.Path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok || !e.Type().IsRegular() || peer.ValidateName(name) != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d.Path, e.Name()))
		if err != nil {
			return nil, err
		}
		out[name] = string(b)
	}
	return out, nil
}

func (d *Dir) file(name string) string { return filepath.Join(d.Path, name+".conf") }

func (d *Dir) write(name, content string) error {
	if err := peer.ValidateName(name); err != nil {
		return err
	}
	tmp := filepath.Join(d.Path, "."+name+".conf.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, d.file(name))
}

func (d *Dir) remove(name string) error {
	if err := os.Remove(d.file(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// restore puts a file back to its old content; ok=false means it didn't exist.
func (d *Dir) restore(name, old string, ok bool) error {
	if ok {
		return d.write(name, old)
	}
	return d.remove(name)
}

// IsRejected reports whether err is BIRD refusing the config (as opposed to
// BIRD being unreachable).
func IsRejected(err error) bool {
	var re *ReplyError
	return errors.As(err, &re)
}

// Sync makes the directory hold desired (peer name → snippet), leaves the
// files of peers in keep as they are and removes every other managed file.
// New content is only reloaded after "configure check" accepts it; a snippet
// BIRD refuses is rolled back and reported in Rejected. If BIRD is
// unreachable, or refuses even the old files, everything is restored and an
// error is returned.
func (d *Dir) Sync(ctx context.Context, desired map[string]string, keep map[string]bool) (*SyncResult, error) {
	res := &SyncResult{Rejected: map[string]error{}}
	current, err := d.Read()
	if err != nil {
		return nil, err
	}
	var deletes, upserts []string
	for name := range current {
		if _, ok := desired[name]; !ok && !keep[name] {
			deletes = append(deletes, name)
		}
	}
	for name, c := range desired {
		if old, ok := current[name]; !ok || old != c {
			upserts = append(upserts, name)
		}
	}
	sort.Strings(deletes)
	sort.Strings(upserts)
	if len(deletes) == 0 && len(upserts) == 0 && d.configured {
		return res, nil
	}

	restoreAll := func(names []string) {
		for _, n := range names {
			old, ok := current[n]
			_ = d.restore(n, old, ok)
		}
	}

	for _, n := range deletes {
		if err := d.remove(n); err != nil {
			restoreAll(deletes)
			return nil, err
		}
	}
	for _, n := range upserts {
		if err := d.write(n, desired[n]); err != nil {
			restoreAll(deletes)
			restoreAll(upserts)
			return nil, err
		}
	}

	err = d.Bird.ConfigureCheck(ctx)
	if err != nil && !IsRejected(err) {
		restoreAll(deletes)
		restoreAll(upserts)
		return nil, err
	}
	if err != nil {
		// Something new is bad. Go back to the old snippets (deletions stay),
		// then add the new ones one by one to find the bad ones.
		restoreAll(upserts)
		if err := d.Bird.ConfigureCheck(ctx); err != nil {
			restoreAll(deletes)
			return nil, fmt.Errorf("bird refuses the config even without the new peer snippets: %w", err)
		}
		var accepted []string
		for _, n := range upserts {
			if err := d.write(n, desired[n]); err != nil {
				restoreAll([]string{n})
				res.Rejected[n] = err
				continue
			}
			if err := d.Bird.ConfigureCheck(ctx); err != nil {
				restoreAll([]string{n})
				if !IsRejected(err) {
					restoreAll(accepted)
					restoreAll(deletes)
					return nil, err
				}
				res.Rejected[n] = err
				continue
			}
			accepted = append(accepted, n)
		}
		upserts = accepted
	}

	if err := d.Bird.Configure(ctx); err != nil {
		return nil, err
	}
	d.configured = true
	res.Written = upserts
	res.Deleted = deletes
	res.Reloaded = true
	return res, nil
}

// Clear removes every managed file and reloads BIRD if it answers. Used when
// this replica is not the leader: BIRD keeps only its static config. The
// files are removed even if BIRD is down, so it starts without peers.
func (d *Dir) Clear(ctx context.Context) (removed []string, err error) {
	current, err := d.Read()
	if err != nil {
		return nil, err
	}
	for n := range current {
		if err := d.remove(n); err != nil {
			return removed, err
		}
		removed = append(removed, n)
	}
	sort.Strings(removed)
	if len(removed) == 0 && d.configured {
		return nil, nil
	}
	if err := d.Bird.Configure(ctx); err != nil {
		return removed, err
	}
	d.configured = true
	return removed, nil
}
