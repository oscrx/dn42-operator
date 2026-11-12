package registry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ASNSource answers whether an aut-num object exists.
type ASNSource interface {
	Exists(asn int64) bool
}

// Set is a fixed set of ASNs (tests, or a list file).
type Set map[int64]bool

// Exists implements ASNSource.
func (s Set) Exists(asn int64) bool { return s[asn] }

// LoadList reads a cached aut-num list: one ASN per line ("AS4242420001"
// or "4242420001"); blank lines and # comments are ignored. Generate it from
// a registry clone with: ls data/aut-num > asns.txt
func LoadList(path string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := Set{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		v := strings.TrimPrefix(strings.ToUpper(line), "AS")
		asn, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not an ASN", path, n, line)
		}
		out[asn] = true
	}
	return out, sc.Err()
}
