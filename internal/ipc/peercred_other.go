//go:build !linux

package ipc

import (
	"errors"
	"net"
)

func readPeerUID(_ net.Conn) (uint32, error) {
	return 0, errors.New("SO_PEERCRED is only supported on Linux Unix sockets")
}
