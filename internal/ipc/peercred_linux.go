//go:build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"
)

func readPeerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var cred *syscall.Ucred
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return cred.Uid, nil
}
