package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

const DefaultClientTimeout = 15 * time.Second

// DialError indicates that the Unix socket could not be connected (e.g. daemon stopped / ENOENT / ECONNREFUSED),
// as opposed to a timeout or error after connecting to a running daemon (N9).
type DialError struct {
	SocketPath string
	Err        error
}

func (e *DialError) Error() string {
	return fmt.Sprintf("connect socket %s: %v", e.SocketPath, e.Err)
}

func (e *DialError) Unwrap() error {
	return e.Err
}

// IsDialError reports whether err failed during initial socket dial (daemon not listening) rather than
// mid-request I/O or deadline timeout, allowing CLI subcommands to avoid racing with a live daemon (N9).
func IsDialError(err error) bool {
	var de *DialError
	return errors.As(err, &de)
}

// SendRequest sends a single JSON Request over a Unix Domain Socket and decodes the JSON Response.
func SendRequest(ctx context.Context, socketPath string, req Request) (Response, error) {
	if socketPath == "" {
		socketPath = DefaultAdminSocketPath
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", socketPath)
	dialCancel()
	if err != nil {
		return Response{}, &DialError{SocketPath: socketPath, Err: err}
	}
	defer conn.Close()

	deadline := time.Now().Add(DefaultClientTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	payload = append(payload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return Response{}, fmt.Errorf("write socket %s: %w", socketPath, err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("decode response from %s: %w", socketPath, err)
	}
	return resp, nil
}
