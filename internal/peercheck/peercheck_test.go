package peercheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/oscrx/dn42-operator/internal/registry"
)

const app = "dn42-autopeer[bot]"

type caseFile struct {
	Author        string   `json:"author"`
	PR            *bool    `json:"pr"`
	OK            bool     `json:"ok"`
	AutoMergeable bool     `json:"autoMergeable"`
	Changes       []string `json:"changes"`
	ErrorContains []string `json:"errorContains"`
}

func readDir(t *testing.T, dir string) map[string]File {
	t.Helper()
	out := map[string]File{}
	if _, err := os.Stat(dir); err != nil {
		return out
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = File{Content: b, Mode: "100644"}
		return nil
	})
	return out
}

func fakeRegistry(t *testing.T) registry.ASNSource {
	s, err := registry.LoadList("testdata/asns.txt")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCases(t *testing.T) {
	dirs, err := filepath.Glob("testdata/cases/*")
	if err != nil || len(dirs) == 0 {
		t.Fatal("no cases", err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, "case.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var c caseFile
			if err := yaml.UnmarshalStrict(b, &c); err != nil {
				t.Fatal(err)
			}
			in := Input{Head: readDir(t, filepath.Join(dir, "head"))}
			if c.PR == nil || *c.PR {
				base := readDir(t, filepath.Join(dir, "base"))
				pr := &PR{Author: c.Author, Base: map[string]File{}}
				for _, ch := range c.Changes {
					st, p, _ := strings.Cut(ch, " ")
					pr.Changes = append(pr.Changes, Change{Status: st[0], Path: p})
					if f, ok := base[p]; ok && st != "A" {
						pr.Base[p] = f
					}
				}
				in.PR = pr
			}
			res := Check(in, &Options{AppLogins: []string{app}, Registry: fakeRegistry(t), LocalASN: 4242423818})
			if res.OK() != c.OK {
				t.Errorf("ok = %v, want %v; errors: %v", res.OK(), c.OK, res.Errors)
			}
			if res.AutoMergeable != c.AutoMergeable {
				t.Errorf("auto-mergeable = %v, want %v; reasons: %v; errors: %v", res.AutoMergeable, c.AutoMergeable, res.NotAutoMergeable, res.Errors)
			}
			var all []string
			for _, e := range res.Errors {
				all = append(all, e.String())
			}
			joined := strings.Join(all, "\n")
			for _, want := range c.ErrorContains {
				if !strings.Contains(joined, want) {
					t.Errorf("no error containing %q in:\n%s", want, joined)
				}
			}
		})
	}
}

func TestRegistryRequired(t *testing.T) {
	head := readDir(t, "testdata/cases/tree-ok/head")
	if res := Check(Input{Head: head}, &Options{}); res.OK() {
		t.Error("passed without a registry")
	}
	if res := Check(Input{Head: head}, &Options{SkipRegistry: true}); !res.OK() {
		t.Errorf("skip-registry: %v", res.Errors)
	}
}

func TestSymlinkRejected(t *testing.T) {
	head := readDir(t, "testdata/cases/tree-ok/head")
	f := head["peers/4242420253-moe.yaml"]
	f.Mode = "120000"
	head["peers/4242420253-moe.yaml"] = f
	if res := Check(Input{Head: head}, &Options{SkipRegistry: true}); res.OK() {
		t.Error("symlink accepted")
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func copyTree(t *testing.T, from, to string) {
	for p, f := range readDir(t, from) {
		dst := filepath.Join(to, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, f.Content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFromGit builds a real repository: main with two peers, a PR branch
// that adds one peer and renames another, and checks the diff and trees.
func TestFromGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main")
	copyTree(t, "testdata/cases/tree-ok/head", dir)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	gitRun(t, dir, "checkout", "-q", "-b", "pr")
	copyTree(t, "testdata/cases/app-add-ok/head", dir)
	if err := os.WriteFile(filepath.Join(dir, "peers", "untracked.txt"), []byte("ignored: not committed"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "peers/4242420010-kio.yaml")
	gitRun(t, dir, "commit", "-q", "-m", "add kio")

	opt := Options{AppLogins: []string{app}, Registry: fakeRegistry(t)}
	in, err := FromGit(dir, "main", "HEAD", app, &opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.PR.Changes) != 1 || in.PR.Changes[0] != (Change{Status: 'A', Path: "peers/4242420010-kio.yaml"}) {
		t.Fatalf("changes: %+v", in.PR.Changes)
	}
	if len(in.Head) != 3 {
		t.Errorf("head tree: %d files (untracked must not count)", len(in.Head))
	}
	res := Check(in, &opt)
	if !res.OK() || !res.AutoMergeable {
		t.Errorf("%+v", res)
	}

	// A second commit renaming moe: delete + add, two files, no auto-merge.
	gitRun(t, dir, "mv", "peers/4242420253-moe.yaml", "peers/4242420253-moe2.yaml")
	gitRun(t, dir, "commit", "-q", "-m", "rename")
	in, err = FromGit(dir, "main", "HEAD", app, &opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.PR.Changes) != 3 {
		t.Errorf("changes after rename: %+v", in.PR.Changes)
	}
	if _, ok := in.PR.Base["peers/4242420253-moe.yaml"]; !ok {
		t.Error("base version of the renamed file missing")
	}
	res = Check(in, &opt)
	if res.OK() || res.AutoMergeable { // name moe2 doesn't match metadata.name moe
		t.Errorf("rename: %+v", res)
	}

	// Tree mode on main.
	in, err = FromGit(dir, "", "main", "", &opt)
	if err != nil || in.PR != nil {
		t.Fatal(err)
	}
	if res := Check(in, &opt); !res.OK() || res.Peers != 2 {
		t.Errorf("main: %+v", res)
	}
}

func TestControlCharactersInPaths(t *testing.T) {
	evil := "peers/a\n::set-output name=auto-mergeable::true\nb.yaml"
	in := Input{
		Head: map[string]File{evil: {Content: []byte("x")}},
		PR:   &PR{Author: app, Changes: []Change{{Status: 'A', Path: evil}}},
	}
	res := Check(in, &Options{AppLogins: []string{app}, SkipRegistry: true})
	if res.OK() || res.AutoMergeable {
		t.Fatalf("passed: %+v", res)
	}
	for _, e := range res.Errors {
		if strings.ContainsAny(e.String(), "\r\n") {
			t.Errorf("finding with a raw line break: %q", e.String())
		}
	}
	if !strings.Contains(res.Errors[0].String(), `"peers/a\n::set-output`) {
		t.Errorf("path not shown quoted: %s", res.Errors[0])
	}
}
