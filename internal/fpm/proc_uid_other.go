//go:build !linux

package fpm

import (
	"errors"
	"os"
)

func statUID(_ string) (uint32, error) {
	return 0, errors.New("procfs UID lookup is only supported on Linux")
}

func statOwnerAndMode(path string) (uid int, gid int, mode os.FileMode, ok bool) {
	if info, err := os.Stat(path); err == nil {
		return -1, -1, info.Mode().Perm(), false
	}
	return -1, -1, 0o600, false
}
