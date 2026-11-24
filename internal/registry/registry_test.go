package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data", "aut-num")
	if err := os.MkdirAll(filepath.Join(dir, "AS4242420009"), 0o755); err != nil { // a directory, not an object
		t.Fatal(err)
	}
	for _, n := range []string{"AS4242420001", "AS4242420002", "README"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("aut-num: "+n+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Exists(4242420001) || !s.Exists(4242420002) || s.Exists(4242420009) || len(s) != 2 {
		t.Errorf("got %v", s)
	}
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Error("missing data/aut-num accepted")
	}
}

func TestLoadList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "asns.txt")
	if err := os.WriteFile(p, []byte("# comment\nAS4242420001\n\n4242420002 # inline\nas4242420003\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadList(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 || !s.Exists(4242420003) {
		t.Errorf("got %v", s)
	}
	if err := os.WriteFile(p, []byte("ASX\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadList(p); err == nil {
		t.Error("bad line accepted")
	}
}
