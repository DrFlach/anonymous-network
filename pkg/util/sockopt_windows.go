//go:build windows

package util

import "syscall"

// SetReuseAddr sets SO_REUSEADDR on the given file descriptor.
func SetReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
