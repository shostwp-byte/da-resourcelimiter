//go:build linux

package fpm

import (
	"fmt"
	"os"
	"syscall"
)

func statUID(path string) (uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	return st.Uid, nil
}

func statOwnerAndMode(path string) (uid int, gid int, mode os.FileMode, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return -1, -1, 0o600, false
	}
	st, castOK := info.Sys().(*syscall.Stat_t)
	if !castOK {
		return -1, -1, info.Mode().Perm(), false
	}
	return int(st.Uid), int(st.Gid), info.Mode().Perm(), true
}

func acquireFileLock(lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
