//go:build !linux

package transit

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Linux is only available on Linux; this stub lets the module build
// elsewhere.
type Linux struct {
	VRF    string
	Source netip.Addr
	Table  int
	Mark   uint32
	Pref   int
}

var errNotLinux = errors.New("transit: only supported on linux")

// Setup fails: not Linux.
func (l *Linux) Setup() error { return errNotLinux }

// Close does nothing.
func (l *Linux) Close() error { return nil }

// Steer fails: not Linux.
func (l *Linux) Steer(string, netip.Addr, []netip.Addr) (func(), error) { return nil, errNotLinux }

// Dial fails: not Linux.
func (l *Linux) Dial(context.Context, netip.AddrPort, bool) (net.Conn, error) {
	return nil, errNotLinux
}
