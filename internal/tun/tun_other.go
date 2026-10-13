//go:build !linux && !windows

package tun

func Open(name string) (Device, error) { return nil, ErrUnsupported }
