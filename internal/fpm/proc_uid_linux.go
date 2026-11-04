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
