//go:build linux

package tunnel

import "syscall"

const soMark = 36 // Linux SO_MARK, stable across supported Linux architectures.

func setSocketMark(fd uintptr, mark uint32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, int(mark))
}
