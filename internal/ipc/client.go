package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// SendRequest sends a single JSON Request over a Unix Domain Socket and decodes the JSON Response.
func SendRequest(ctx context.Context, socketPath string, req Request) (Response, error) {
	if socketPath == "" {
		socketPath = DefaultAdminSocketPath
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(10 * time.Second)
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
