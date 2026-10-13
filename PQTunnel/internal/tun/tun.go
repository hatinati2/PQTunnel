// Package tun provides layer-3 packet devices. It does not configure host routes or DNS.
package tun

import (
	"errors"
	"io"
	"os"
)

var ErrUnsupported = errors.New("TUN adapter unsupported on this platform or unavailable")

type Device interface{ io.ReadWriteCloser }

// FromFD wraps an already-established TUN file descriptor (used by Android VpnService).
func FromFD(fd uintptr) (Device, error) {
	f := os.NewFile(fd, "pqtunnel-tun")
	if f == nil {
		return nil, ErrUnsupported
	}
	return f, nil
}
