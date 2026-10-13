//go:build windows

package tun

import (
	"fmt"
	"syscall"

	"golang.zx2c4.com/wintun"
)

type windowsDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	waitProc *syscall.LazyProc
}

// Open attaches to an existing Wintun adapter. The Wintun DLL/driver must be provisioned separately.
func Open(name string) (Device, error) {
	a, err := wintun.OpenAdapter(name)
	if err != nil {
		return nil, fmt.Errorf("open Wintun adapter %q (provision it with the official Wintun driver first): %w", name, err)
	}
	s, err := a.StartSession(wintun.RingCapacityMin)
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	dll := syscall.NewLazyDLL("kernel32.dll")
	return &windowsDevice{adapter: a, session: s, waitProc: dll.NewProc("WaitForSingleObject")}, nil
}

func (d *windowsDevice) Read(p []byte) (int, error) {
	for {
		packet, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			d.session.ReleaseReceivePacket(packet)
			if n != len(packet) {
				return 0, fmt.Errorf("TUN read buffer too small")
			}
			return n, nil
		}
		h := d.session.ReadWaitEvent()
		ret, _, callErr := d.waitProc.Call(uintptr(h), ^uintptr(0))
		if ret == ^uintptr(0) {
			return 0, callErr
		}
	}
}

func (d *windowsDevice) Write(p []byte) (int, error) {
	packet, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(packet, p)
	d.session.SendPacket(packet)
	return len(p), nil
}

func (d *windowsDevice) Close() error { d.session.End(); return d.adapter.Close() }
