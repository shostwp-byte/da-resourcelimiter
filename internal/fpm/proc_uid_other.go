//go:build !linux

package fpm

import "errors"

func statUID(_ string) (uint32, error) {
	return 0, errors.New("procfs UID lookup is only supported on Linux")
}
