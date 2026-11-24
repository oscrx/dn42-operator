//go:build linux

package transit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Linux steers probe connections with a routing table of their own: a rule
// sends packets carrying Mark to Table, which holds /128 routes to the
// targets via the probed peer's link and an unreachable default (so a
// missing route fails closed instead of taking the normal path). The mark
// is set before connect, so the SYN is steered too: a firewall that never
// sees the connection start lets the rest through, and would hide the
// problem. Nothing else carries the mark, so real traffic is untouched.
type Linux struct {
	VRF    string     // the sockets are bound to it
	Source netip.Addr // our address in the VRF the probes come from
	Table  int
	Mark   uint32
	Pref   int // rule priority; must be ahead of the l3mdev rule (1000)
}

var _ Net = (*Linux)(nil)

func (l *Linux) rule() *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V6
	r.Priority = l.Pref
	r.Table = l.Table
	r.Mark = l.Mark
	mask := uint32(0xffffffff)
	r.Mask = &mask
	return r
}

func defaultRoute() *net.IPNet { return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)} }

// Setup installs the rule and the table's unreachable default; repeatable.
func (l *Linux) Setup() error {
	if l.Pref <= 0 || l.Pref >= 1000 || l.Table <= 0 || l.Mark == 0 {
		return fmt.Errorf("transit: need 0 < pref < 1000, a table and a mark")
	}
	r := l.rule()
	have, err := netlink.RuleListFiltered(netlink.FAMILY_V6, r,
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_MARK)
	if err != nil {
		return fmt.Errorf("transit: list rules: %w", err)
	}
	if len(have) == 0 {
		if err := netlink.RuleAdd(r); err != nil {
			return fmt.Errorf("transit: add rule: %w", err)
		}
	}
	err = netlink.RouteReplace(&netlink.Route{Family: netlink.FAMILY_V6, Table: l.Table,
		Type: unix.RTN_UNREACHABLE, Dst: defaultRoute()})
	if err != nil {
		return fmt.Errorf("transit: unreachable default in table %d: %w", l.Table, err)
	}
	return nil
}

// Close removes the rule and everything in the table.
func (l *Linux) Close() error {
	var errs []error
	if err := netlink.RuleDel(l.rule()); err != nil && !errors.Is(err, unix.ENOENT) {
		errs = append(errs, err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: l.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for i := range routes {
		if err := netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Steer routes dsts through gw on iface until undo runs.
func (l *Linux) Steer(iface string, gw netip.Addr, dsts []netip.Addr) (undo func(), err error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("transit: %s: %w", iface, err)
	}
	var added []*netlink.Route
	undo = func() {
		for _, r := range added {
			_ = netlink.RouteDel(r)
		}
	}
	for _, d := range dsts {
		r := &netlink.Route{Family: netlink.FAMILY_V6, Table: l.Table, LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{IP: d.AsSlice(), Mask: net.CIDRMask(128, 128)}, Gw: gw.AsSlice()}
		if err := netlink.RouteReplace(r); err != nil {
			undo()
			return nil, fmt.Errorf("transit: route %s via %s: %w", d, iface, err)
		}
		added = append(added, r)
	}
	return undo, nil
}

// Dial connects from Source inside the VRF, carrying the mark when steer is
// true.
func (l *Linux) Dial(ctx context.Context, dst netip.AddrPort, steer bool) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: l.Source.AsSlice()},
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, l.VRF); serr != nil {
					return
				}
				if steer {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(l.Mark))
				}
			})
			return errors.Join(err, serr)
		},
	}
	return d.DialContext(ctx, "tcp6", dst.String())
}
