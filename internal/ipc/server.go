package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRequestBytes = 64 * 1024

// RequestHandler processes decoded IPC requests for Admin and User sockets.
type RequestHandler interface {
	HandleAdminRequest(ctx context.Context, req Request) Response
	HandleUserRequest(ctx context.Context, peerUID uint32, req Request) Response
}

// PeerUIDFunc extracts the kernel-authenticated OS UID of a connected Unix socket client.
type PeerUIDFunc func(conn net.Conn) (uint32, error)

// Server listens on the privileged Admin Unix Socket (0660 root:diradmin)
// and the read-only Customer Unix Socket (0666 with SO_PEERCRED isolation).
type Server struct {
	AdminSocketPath string
	UserSocketPath  string
	GroupFilePath   string
	Handler         RequestHandler
	GetPeerUID      PeerUIDFunc

	wg sync.WaitGroup
}

func NewServer(adminSock, userSock string, handler RequestHandler) *Server {
	if adminSock == "" {
		adminSock = DefaultAdminSocketPath
	}
	if userSock == "" {
		userSock = DefaultUserSocketPath
	}
	return &Server{
		AdminSocketPath: adminSock,
		UserSocketPath:  userSock,
		GroupFilePath:   "/etc/group",
		Handler:         handler,
		GetPeerUID:      readPeerUID,
	}
}

// Start binds both Unix sockets and serves requests until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	adminLn, err := listenUnixSocket(s.AdminSocketPath, 0o660, lookupGroupGID(s.GroupFilePath, "diradmin"))
	if err != nil {
		return fmt.Errorf("listen admin socket %s: %w", s.AdminSocketPath, err)
	}

	userLn, err := listenUnixSocket(s.UserSocketPath, 0o666, -1)
	if err != nil {
		_ = adminLn.Close()
		_ = os.Remove(s.AdminSocketPath)
		return fmt.Errorf("listen user socket %s: %w", s.UserSocketPath, err)
	}

	go func() {
		<-ctx.Done()
		_ = adminLn.Close()
		_ = userLn.Close()
		_ = os.Remove(s.AdminSocketPath)
		_ = os.Remove(s.UserSocketPath)
	}()

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, adminLn, true)
	}()
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, userLn, false)
	}()

	return nil
}

// Wait blocks until all socket accept loops and active client handlers finish.
func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, isAdminSocket bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("ipc accept error (admin=%v): %v", isAdminSocket, err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.ServeConn(ctx, c, isAdminSocket)
		}(conn)
	}
}

// ServeConn handles a single JSON request-response exchange on conn.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn, isAdminSocket bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var req Request
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestBytes))
	if err := dec.Decode(&req); err != nil {
		writeResponse(conn, Response{OK: false, Error: "invalid JSON request: " + err.Error()})
		return
	}

	var resp Response
	if isAdminSocket {
		resp = s.Handler.HandleAdminRequest(ctx, req)
	} else {
		peerUID, err := s.GetPeerUID(conn)
		if err != nil {
			writeResponse(conn, Response{OK: false, Error: "unable to verify peer kernel credentials: " + err.Error()})
			return
		}
		resp = s.Handler.HandleUserRequest(ctx, peerUID, req)
	}

	writeResponse(conn, resp)
}

func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		data = []byte(`{"ok":false,"error":"internal JSON marshal error"}`)
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func listenUnixSocket(sockPath string, mode os.FileMode, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	if gid >= 0 {
		// Best-effort chown root:diradmin when running as root on DirectAdmin servers
		_ = os.Chown(sockPath, 0, gid)
	} else if mode == 0o660 {
		// If diradmin group does not exist on host, tighten to 0600 root-only
		mode = 0o600
	}

	if err := os.Chmod(sockPath, mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, err
	}
	return ln, nil
}

func lookupGroupGID(groupFilePath, groupName string) int {
	if groupFilePath == "" {
		groupFilePath = "/etc/group"
	}
	f, err := os.Open(groupFilePath)
	if err != nil {
		return -1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[0] == groupName {
			if gid, err := strconv.Atoi(parts[2]); err == nil {
				return gid
			}
		}
	}
	return -1
}
