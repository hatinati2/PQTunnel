//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

// Open opens /dev/net/tun and attaches/creates a layer-3 TUN interface.
// Interface addresses, routes, DNS and firewall policy are intentionally not changed here.
func Open(name string) (Device, error) {
	if name == "" || len(name) >= 16 || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("invalid TUN interface name %q (max 15 bytes)", name)
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req [40]byte // Linux amd64/arm64 ifreq layout
	copy(req[:16], name)
	binary.LittleEndian.PutUint16(req[16:18], iffTUN|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("TUNSETIFF %q: %w", name, errno)
	}
	return f, nil
}
