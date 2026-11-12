package peercheck

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func git(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// readTree returns the files under dir at rev, as committed (never the
// worktree, so nothing the PR leaves untracked can matter).
func readTree(repo, rev, dir string) (map[string]File, error) {
	out, err := git(repo, "ls-tree", "-r", "-z", rev, "--", dir+"/")
	if err != nil {
		return nil, err
	}
	files := map[string]File{}
	for _, ent := range strings.Split(string(out), "\x00") {
		if ent == "" {
			continue
		}
		meta, p, ok := strings.Cut(ent, "\t")
		f := strings.Fields(meta) // mode type object
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree entry %q", ent)
		}
		file := File{Mode: f[0]}
		if f[1] == "blob" {
			if file.Content, err = git(repo, "cat-file", "blob", f[2]); err != nil {
				return nil, err
			}
		}
		files[p] = file
	}
	return files, nil
}

// FromGit builds the input from a repository: the tree at head, and when
// base is set, the PR diff base...head (merge base) with the base versions of
// the touched peer files.
func FromGit(repo, base, head, author string, opt Options) (Input, error) {
	opt.defaults()
	if head == "" {
		head = "HEAD"
	}
	tree, err := readTree(repo, head, opt.PeersDir)
	if err != nil {
		return Input{}, err
	}
	in := Input{Head: tree}
	if base == "" {
		return in, nil
	}
	mb, err := git(repo, "merge-base", base, head)
	if err != nil {
		return Input{}, err
	}
	mergeBase := strings.TrimSpace(string(mb))
	out, err := git(repo, "diff", "--name-status", "--no-renames", "-z", mergeBase, head)
	if err != nil {
		return Input{}, err
	}
	pr := &PR{Author: author, Base: map[string]File{}}
	fields := strings.Split(string(out), "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		st, p := fields[i], fields[i+1]
		if st == "" {
			break
		}
		pr.Changes = append(pr.Changes, Change{Status: st[0], Path: p})
	}
	baseTree, err := readTree(repo, mergeBase, opt.PeersDir)
	if err != nil {
		return Input{}, err
	}
	for _, c := range pr.Changes {
		if f, ok := baseTree[c.Path]; ok {
			pr.Base[c.Path] = f
		}
	}
	in.PR = pr
	return in, nil
}

// FromDir reads the peers dir from disk (local runs before committing).
func FromDir(dir string, opt Options) (Input, error) {
	opt.defaults()
	in := Input{Head: map[string]File{}}
	root := filepath.Join(dir, filepath.FromSlash(opt.PeersDir))
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		f := File{Mode: "100644"}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			f.Mode = "120000"
		} else if f.Content, err = os.ReadFile(p); err != nil {
			return err
		}
		in.Head[filepath.ToSlash(rel)] = f
		return nil
	})
	return in, err
}
