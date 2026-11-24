// Package registry answers whether an ASN has an aut-num object in the DN42
// registry, from a registry clone or a plain ASN list.
package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

var autNumRe = regexp.MustCompile(`^AS(\d{1,10})$`)

// LoadDir lists the aut-num objects of a registry clone (data/aut-num/AS*).
// Only the file names matter, so a tree-only checkout is enough.
func LoadDir(path string) (Set, error) {
	ents, err := os.ReadDir(filepath.Join(path, "data", "aut-num"))
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	out := Set{}
	for _, e := range ents {
		m := autNumRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		if asn, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			out[asn] = true
		}
	}
	return out, nil
}
