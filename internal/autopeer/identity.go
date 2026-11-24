package autopeer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/oscrx/dn42-operator/internal/peer"
	"github.com/oscrx/dn42-operator/internal/registry"
)

var providerNameRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

// Identity is a normalised login: who, and which ASNs they may manage.
type Identity struct {
	Provider string   `json:"p"`
	Subject  string   `json:"s"`
	Name     string   `json:"n,omitempty"`
	Mntners  []string `json:"m,omitempty"`
	ASNs     []int64  `json:"a"`
}

// DisplayName is the name to show: the name claim, else the subject.
func (id *Identity) DisplayName() string {
	if id.Name != "" {
		return id.Name
	}
	return id.Subject
}

// Login describes the identity for a PR body: the name, the provider, and
// the subject when it differs from the name.
func (id *Identity) Login() string {
	if id.Name == "" || id.Name == id.Subject {
		return fmt.Sprintf("%s (%s)", mdCode(id.Subject), id.Provider)
	}
	return fmt.Sprintf("%s (%s, subject %s)", mdCode(id.Name), id.Provider, mdCode(id.Subject))
}

// May reports whether the identity may manage asn.
func (id *Identity) May(asn int64) bool {
	for _, a := range id.ASNs {
		if a == asn {
			return true
		}
	}
	return false
}

// lookup follows a dotted path through nested claims.
func lookup(claims map[string]any, path string) (any, bool) {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// strings flattens a claim value: string (split on comma/space), number or list.
func claimStrings(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	case float64:
		return []string{strconv.FormatFloat(x, 'f', -1, 64)}
	case json.Number:
		return []string{x.String()}
	case int64:
		return []string{strconv.FormatInt(x, 10)}
	case int:
		return []string{strconv.Itoa(x)}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, claimStrings(e)...)
		}
		return out
	case []string:
		return x
	}
	return nil
}

// parseASN accepts "AS4242420001", "as4242420001" and "4242420001".
func parseASN(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || !peer.IsDN42ASN(n) {
		return 0, fmt.Errorf("%q is not a DN42 ASN", s)
	}
	return n, nil
}

// IdentityFromClaims builds the identity from a provider's claims: ASNs from
// the ASN claim, plus the ASNs the registry lists for each mntner claim.
// Unparseable values are ignored; an identity without any ASN is an error.
func IdentityFromClaims(p *ProviderConfig, claims map[string]any, reg *registry.Registry) (*Identity, error) {
	id := &Identity{Provider: p.Name}
	if v, ok := lookup(claims, p.Claims.Subject); ok {
		if s := claimStrings(v); len(s) > 0 {
			id.Subject = s[0]
		}
	}
	if id.Subject == "" {
		return nil, fmt.Errorf("provider %s: no %q claim", p.Name, p.Claims.Subject)
	}
	if p.Claims.Name != "" {
		if v, ok := lookup(claims, p.Claims.Name); ok {
			if s := claimStrings(v); len(s) > 0 {
				id.Name = s[0]
			}
		}
	}
	set := map[int64]bool{}
	if p.Claims.ASN != "" {
		if v, ok := lookup(claims, p.Claims.ASN); ok {
			for _, s := range claimStrings(v) {
				if n, err := parseASN(s); err == nil {
					set[n] = true
				}
			}
		}
	}
	if p.Claims.Mntner != "" {
		if v, ok := lookup(claims, p.Claims.Mntner); ok {
			for _, m := range claimStrings(v) {
				m = strings.ToUpper(m)
				id.Mntners = append(id.Mntners, m)
				if reg != nil {
					for _, n := range reg.ASNsFor(m) {
						if peer.IsDN42ASN(n) {
							set[n] = true
						}
					}
				}
			}
		}
	}
	for n := range set {
		id.ASNs = append(id.ASNs, n)
	}
	sort.Slice(id.ASNs, func(i, j int) bool { return id.ASNs[i] < id.ASNs[j] })
	if len(id.ASNs) == 0 {
		return nil, fmt.Errorf("provider %s returned no ASN for %s (claims checked: asn=%q mntner=%q)",
			p.Name, id.Subject, p.Claims.ASN, p.Claims.Mntner)
	}
	return id, nil
}
