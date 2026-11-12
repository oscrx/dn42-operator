//go:build linux

package netdev

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Linux manages links in the current network namespace.
type Linux struct {
	// SysctlRoot is /proc/sys/net/ipv6/conf by default.
	SysctlRoot string
}

// NewLinux returns the Linux backend.
func NewLinux() *Linux { return &Linux{SysctlRoot: "/proc/sys/net/ipv6/conf"} }

func (l *Linux) wg() (*wgctrl.Client, error) { return wgctrl.New() }

// ListManaged returns all wireguard links with the managed alias.
func (l *Linux) ListManaged() ([]State, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var out []State
	for _, ln := range links {
		if ln.Attrs().Alias != Alias || ln.Type() != "wireguard" {
			continue
		}
		s, err := l.inspect(ln)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, nil
}

// Inspect returns the state of a link, nil if it doesn't exist.
func (l *Linux) Inspect(name string) (*State, error) {
	ln, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, fmt.Errorf("get link %s: %w", name, err)
	}
	return l.inspect(ln)
}

func (l *Linux) inspect(ln netlink.Link) (*State, error) {
	a := ln.Attrs()
	s := &State{
		Name:    a.Name,
		Alias:   a.Alias,
		Up:      a.Flags&net.FlagUp != 0,
		Sysctls: map[string]string{},
	}
	if a.MasterIndex != 0 {
		m, err := netlink.LinkByIndex(a.MasterIndex)
		if err != nil {
			return nil, fmt.Errorf("get master of %s: %w", a.Name, err)
		}
		s.Master = m.Attrs().Name
	}
	addrs, err := netlink.AddrList(ln, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list addresses of %s: %w", a.Name, err)
	}
	for _, ad := range addrs {
		ip, ok := netip.AddrFromSlice(ad.IP)
		if !ok {
			continue
		}
		ones, _ := ad.Mask.Size()
		s.Addresses = append(s.Addresses, netip.PrefixFrom(ip.Unmap(), ones))
	}
	for k := range Sysctls {
		b, err := os.ReadFile(filepath.Join(l.SysctlRoot, a.Name, k))
		if err != nil {
			return nil, fmt.Errorf("read sysctl %s of %s: %w", k, a.Name, err)
		}
		s.Sysctls[k] = strings.TrimSpace(string(b))
	}
	if ln.Type() != "wireguard" {
		return s, nil
	}
	c, err := l.wg()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(a.Name)
	if err != nil {
		return nil, fmt.Errorf("wireguard %s: %w", a.Name, err)
	}
	s.PrivateKey = dev.PrivateKey
	s.ListenPort = dev.ListenPort
	for _, p := range dev.Peers {
		s.Peers = append(s.Peers, WGPeer{
			PublicKey:     p.PublicKey,
			Endpoint:      p.Endpoint,
			AllowedIPs:    p.AllowedIPs,
			Keepalive:     p.PersistentKeepaliveInterval,
			LastHandshake: p.LastHandshakeTime,
		})
	}
	return s, nil
}

// Ensure creates the link if needed and applies the diff.
func (l *Linux) Ensure(spec *Spec, now time.Time) (*Plan, error) {
	vrf, err := netlink.LinkByName(spec.VRF)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrVRFMissing, spec.VRF)
	}
	if vrf.Type() != "vrf" {
		return nil, fmt.Errorf("%w: %s is a %s link, not a vrf", ErrVRFMissing, spec.VRF, vrf.Type())
	}

	st, err := l.Inspect(spec.Name)
	if err != nil {
		return nil, err
	}
	created := false
	if st == nil {
		ln := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: spec.Name}, LinkType: "wireguard"}
		if err := netlink.LinkAdd(ln); err != nil {
			return nil, fmt.Errorf("create %s: %w", spec.Name, err)
		}
		lnk, err := netlink.LinkByName(spec.Name)
		if err != nil {
			return nil, err
		}
		// Mark it ours before anything else, so a crash right after leaves
		// a link that cleanup recognises.
		if err := netlink.LinkSetAlias(lnk, Alias); err != nil {
			_ = netlink.LinkDel(lnk)
			return nil, fmt.Errorf("set alias on %s: %w", spec.Name, err)
		}
		created = true
		if st, err = l.Inspect(spec.Name); err != nil {
			return nil, err
		}
	} else if !st.Managed() {
		return nil, fmt.Errorf("%s: %w", spec.Name, ErrNotManaged)
	}

	plan := Diff(st, spec, now)
	if created {
		plan.Description = append([]string{"create"}, plan.Description...)
	}
	if plan.Empty() {
		return plan, nil
	}
	if err := l.apply(st, spec, plan); err != nil {
		return plan, err
	}
	// Enslaving to a VRF cycles the link, which can drop IPv6 addresses;
	// re-check once so the address is back in the same pass.
	if plan.SetMaster {
		st, err := l.Inspect(spec.Name)
		if err != nil {
			return plan, err
		}
		again := Diff(st, spec, now)
		if !again.Empty() {
			if err := l.apply(st, spec, again); err != nil {
				return plan, err
			}
		}
	}
	return plan, nil
}

func (l *Linux) apply(st *State, spec *Spec, plan *Plan) error {
	ln, err := netlink.LinkByName(spec.Name)
	if err != nil {
		return err
	}
	if plan.SetAlias {
		if err := netlink.LinkSetAlias(ln, Alias); err != nil {
			return fmt.Errorf("set alias on %s: %w", spec.Name, err)
		}
	}
	if plan.WireGuard != nil {
		c, err := l.wg()
		if err != nil {
			return err
		}
		err = c.ConfigureDevice(spec.Name, *plan.WireGuard)
		c.Close()
		if err != nil {
			return fmt.Errorf("configure wireguard %s: %w", spec.Name, err)
		}
	}
	if plan.SetMaster {
		vrf, err := netlink.LinkByName(spec.VRF)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrVRFMissing, spec.VRF)
		}
		if err := netlink.LinkSetMasterByIndex(ln, vrf.Attrs().Index); err != nil {
			return fmt.Errorf("set master of %s: %w", spec.Name, err)
		}
	}
	for k, v := range plan.SetSysctls {
		p := filepath.Join(l.SysctlRoot, spec.Name, k)
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			return fmt.Errorf("set sysctl %s of %s: %w", k, spec.Name, err)
		}
	}
	for _, a := range plan.DelAddrs {
		if err := netlink.AddrDel(ln, toNlAddr(a)); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("delete address %s from %s: %w", a, spec.Name, err)
		}
	}
	for _, a := range plan.AddAddrs {
		na := toNlAddr(a)
		if a.Addr().IsLinkLocalUnicast() {
			na.Scope = unix.RT_SCOPE_LINK
		}
		if err := netlink.AddrAdd(ln, na); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add address %s to %s: %w", a, spec.Name, err)
		}
	}
	if plan.SetUp {
		if err := netlink.LinkSetUp(ln); err != nil {
			return fmt.Errorf("set %s up: %w", spec.Name, err)
		}
	}
	return nil
}

func toNlAddr(p netip.Prefix) *netlink.Addr {
	bits := 128
	if p.Addr().Is4() {
		bits = 32
	}
	return &netlink.Addr{IPNet: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), bits)}}
}

// Delete removes a managed link.
func (l *Linux) Delete(name string) error {
	ln, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	if ln.Attrs().Alias != Alias {
		return fmt.Errorf("%s: %w", name, ErrNotManaged)
	}
	if err := netlink.LinkDel(ln); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}
