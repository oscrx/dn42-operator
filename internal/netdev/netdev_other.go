//go:build !linux

package netdev

import (
	"errors"
	"time"
)

// Linux is only available on Linux; this stub lets the module build and the
// unit tests run elsewhere.
type Linux struct{ SysctlRoot string }

var errNotLinux = errors.New("netdev: only supported on linux")

// NewLinux returns a backend that always fails.
func NewLinux() *Linux { return &Linux{} }

func (l *Linux) ListManaged() ([]State, error)          { return nil, errNotLinux }
func (l *Linux) Inspect(string) (*State, error)         { return nil, errNotLinux }
func (l *Linux) Ensure(*Spec, time.Time) (*Plan, error) { return nil, errNotLinux }
func (l *Linux) Delete(string) error                    { return errNotLinux }
