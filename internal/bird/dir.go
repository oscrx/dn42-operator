package bird

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// ConfigFile is BIRD's main config (optional): the file BIRD itself
	// loads. When its content changes, the next Sync runs configure check +
	// configure, so edits reach BIRD by reconfiguring, never by restarting it.
	ConfigFile string
	// ConfigSource (optional) is where new bird.conf versions appear (the
	// operator's ConfigMap mount). Sync copies it to ConfigFile, but only
	// after BIRD's configure check accepts it; a rejected version is rolled
	// back. One file shared with BIRD means BIRD never reconfigures from a
	// copy older than the one that was checked.
	ConfigSource string

	configured bool   // a configure succeeded since start
	configHash string // ConfigFile hash at the last successful configure
}

func (d *Dir) currentConfigHash() string {
	if d.ConfigFile == "" {
		return ""
	}
	b, err := os.ReadFile(d.ConfigFile)
	if err != nil {
		return "unreadable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// upToDate: BIRD was configured since start and bird.conf hasn't changed.
func (d *Dir) upToDate(hash string) bool { return d.configured && hash == d.configHash }

// ErrConfigRejected wraps BIRD refusing a new bird.conf from ConfigSource.
var ErrConfigRejected = errors.New("bird refused the new bird.conf, kept the old one")

// syncConfigFile copies a new ConfigSource version into ConfigFile once BIRD
// accepts it. It returns ErrConfigRejected (wrapped) when BIRD refuses it,
// or the error when BIRD can't be asked; both leave ConfigFile as it was.
func (d *Dir) syncConfigFile(ctx context.Context) error {
	if d.ConfigSource == "" || d.ConfigFile == "" {
		return nil
	}
	src, err := os.ReadFile(d.ConfigSource)
	if err != nil {
		return fmt.Errorf("read %s: %w", d.ConfigSource, err)
	}
	old, err := os.ReadFile(d.ConfigFile)
	hadOld := err == nil
	if hadOld && bytes.Equal(old, src) {
		return nil
	}
	put := func(b []byte) error {
		tmp := d.ConfigFile + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, d.ConfigFile)
	}
	if err := put(src); err != nil {
		return err
	}
	if err := d.Bird.ConfigureCheck(ctx); err != nil {
		if hadOld {
			_ = put(old)
		}
		if IsRejected(err) {
			return fmt.Errorf("%w: %w", ErrConfigRejected, err)
		}
		return err
	}
	return nil
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
	// ConfigChanged is true when the reload was (also) for a changed bird.conf.
	ConfigChanged bool
	// ConfigRejected is set when BIRD refused a new bird.conf version; the
	// old one stays loaded and the peer snippets are still synced.
	ConfigRejected error
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
	if err := d.syncConfigFile(ctx); err != nil {
		if !errors.Is(err, ErrConfigRejected) {
			return nil, err
		}
		res.ConfigRejected = err
	}
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
	hash := d.currentConfigHash()
	if len(deletes) == 0 && len(upserts) == 0 && d.upToDate(hash) {
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
		// Not up to date any more: the next Sync configures again even if
		// nothing else changes.
		d.configured = false
		return nil, err
	}
	res.ConfigChanged = d.configured && hash != d.configHash
	d.configured, d.configHash = true, hash
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
	hash := d.currentConfigHash()
	if len(removed) == 0 && d.upToDate(hash) {
		return nil, nil
	}
	if err := d.Bird.Configure(ctx); err != nil {
		d.configured = false
		return removed, err
	}
	d.configured, d.configHash = true, hash
	return removed, nil
}
