//go:build !linux

package tunnel

import "fmt"

func setSocketMark(fd uintptr, mark uint32) error {
	if mark == 0 {
		return nil
	}
	return fmt.Errorf("--socket-mark is only supported on Linux")
}
