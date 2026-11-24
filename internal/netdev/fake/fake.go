// Package fake is an in-memory netdev.Manager for tests.
package fake

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/oscrx/dn42-operator/internal/netdev"
)

// Manager keeps links in memory and applies plans from netdev.Diff.
type Manager struct {
	mu    sync.Mutex
	Links map[string]*netdev.State
	VRFs  []string
	// Calls records Ensure/Delete calls ("ensure wg-x", "delete wg-x").
	Calls []string
	// Err, if set, is returned by every call.
	Err error
}

// New returns a fake with the given VRFs.
func New(vrfs ...string) *Manager {
	return &Manager{Links: map[string]*netdev.State{}, VRFs: vrfs}
}

// AddForeign adds a link without the managed alias.
func (m *Manager) AddForeign(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Links[name] = &netdev.State{Name: name, Sysctls: map[string]string{}}
}

// ListManaged returns the links with the managed alias.
func (m *Manager) ListManaged() ([]netdev.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return nil, m.Err
	}
	var out []netdev.State
	for _, s := range m.Links {
		if s.Managed() {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Inspect returns a copy of a link, nil if missing.
func (m *Manager) Inspect(name string) (*netdev.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return nil, m.Err
	}
	s, ok := m.Links[name]
	if !ok {
		return nil, nil
	}
	c := *s
	return &c, nil
}

// Ensure applies netdev.Diff to the in-memory link.
func (m *Manager) Ensure(spec *netdev.Spec, now time.Time) (*netdev.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, "ensure "+spec.Name)
	if m.Err != nil {
		return nil, m.Err
	}
	if !slices.Contains(m.VRFs, spec.VRF) {
		return nil, fmt.Errorf("%w: %s", netdev.ErrVRFMissing, spec.VRF)
	}
	s, ok := m.Links[spec.Name]
	if !ok {
		s = &netdev.State{Name: spec.Name, Alias: netdev.Alias, Sysctls: map[string]string{}}
		m.Links[spec.Name] = s
	} else if !s.Managed() {
		return nil, fmt.Errorf("%s: %w", spec.Name, netdev.ErrNotManaged)
	}
	p := netdev.Diff(s, spec, now)
	s.Alias = netdev.Alias
	s.Master = spec.VRF
	for k, v := range netdev.Sysctls {
		s.Sysctls[k] = v
	}
	s.Addresses = append(s.Addresses[:0], spec.Address)
	s.Up = true
	if spec.MTU != 0 {
		s.MTU = spec.MTU
	}
	s.PrivateKey = spec.PrivateKey
	s.ListenPort = spec.ListenPort
	hs := time.Time{}
	ep := spec.Endpoint
	if len(s.Peers) == 1 && s.Peers[0].PublicKey == spec.PeerPublicKey {
		hs = s.Peers[0].LastHandshake
		if ep == nil {
			ep = s.Peers[0].Endpoint // like the kernel: a learned endpoint stays
		}
	}
	s.Peers = []netdev.WGPeer{{PublicKey: spec.PeerPublicKey, Endpoint: ep,
		AllowedIPs: netdev.AllowedIPs, Keepalive: netdev.Keepalive, LastHandshake: hs}}
	return p, nil
}

// Roam sets where a link's peer is now seen, as WireGuard does when packets
// arrive from a new address.
func (m *Manager) Roam(name string, ep *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.Links[name]; ok && len(s.Peers) == 1 {
		s.Peers[0].Endpoint = ep
	}
}

// Delete removes a managed link; foreign links are refused.
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, "delete "+name)
	if m.Err != nil {
		return m.Err
	}
	s, ok := m.Links[name]
	if !ok {
		return nil
	}
	if !s.Managed() {
		return fmt.Errorf("%s: %w", name, netdev.ErrNotManaged)
	}
	delete(m.Links, name)
	return nil
}
