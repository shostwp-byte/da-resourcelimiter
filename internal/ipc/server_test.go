package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type stubHandler struct {
	decodedCount int
}

func (s *stubHandler) AuthorizeSocketPeer(peerUID uint32, isAdminSocket bool) error {
	if isAdminSocket && peerUID != 0 && peerUID != 1001 {
		return errors.New("permission denied: caller UID is not an administrator")
	}
	return nil
}

func (s *stubHandler) HandleAdminRequest(_ context.Context, peerUID uint32, req Request) Response {
	s.decodedCount++
	if peerUID != 0 && peerUID != 1001 {
		return Response{OK: false, Error: "permission denied: non-admin UID"}
	}
	return Response{OK: true, Message: "admin:" + req.Action}
}

func (s *stubHandler) HandleUserRequest(_ context.Context, peerUID uint32, req Request) Response {
	s.decodedCount++
	if req.Action != ActionGetUserStats {
		return Response{OK: false, Error: "permission denied"}
	}
	return Response{OK: true, Data: map[string]interface{}{"peer_uid": peerUID}}
}

func TestServeConnPreDecodeAuthRateLimitAndIsolation(t *testing.T) {
	handler := &stubHandler{}
	srv := NewServer("", "", handler)
	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return 1005, nil
	}

	// 1. Test Admin Socket rejects non-admin UID (1005) via PeerAuthorizer BEFORE reading/decoding JSON (S5)
	c0, s0 := net.Pipe()
	go srv.ServeConn(context.Background(), s0, true)

	// Do not even write JSON from client — server should immediately emit permission denied and close!
	var blockedAdminResp Response
	if err := json.NewDecoder(c0).Decode(&blockedAdminResp); err != nil {
		t.Fatalf("decode pre-decode blocked admin response: %v", err)
	}
	_ = c0.Close()
	if blockedAdminResp.OK || handler.decodedCount != 0 {
		t.Fatalf("expected pre-decode rejection without invoking handler, got resp=%+v decoded=%d", blockedAdminResp, handler.decodedCount)
	}

	// 2. Test Admin Socket allows DirectAdmin admin UID (1001)
	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return 1001, nil
	}
	c1, s1 := net.Pipe()
	go srv.ServeConn(context.Background(), s1, true)

	_ = json.NewEncoder(c1).Encode(Request{Action: ActionApplyUserLimits, Username: "vinahost"})
	var adminResp Response
	if err := json.NewDecoder(c1).Decode(&adminResp); err != nil {
		t.Fatalf("decode admin response: %v", err)
	}
	_ = c1.Close()
	if !adminResp.OK || adminResp.Message != "admin:apply_user_limits" {
		t.Fatalf("unexpected admin response: %+v", adminResp)
	}

	// 3. Test User Socket blocks privileged actions
	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return 1005, nil
	}
	c2, s2 := net.Pipe()
	go srv.ServeConn(context.Background(), s2, false)

	_ = json.NewEncoder(c2).Encode(Request{Action: ActionUnblockPenalty, Username: "vinahost"})
	var deniedResp Response
	if err := json.NewDecoder(c2).Decode(&deniedResp); err != nil {
		t.Fatalf("decode denied response: %v", err)
	}
	_ = c2.Close()
	if deniedResp.OK {
		t.Fatalf("expected user socket to deny privileged action, got %+v", deniedResp)
	}

	// 4. Test User Socket per-UID sliding-window rate limiter (S5)
	srv.UserRateWindow = 10 * time.Second
	srv.UserRateLimitBurst = 2 // 1 request already consumed above by UID 1005

	c3, s3 := net.Pipe()
	go srv.ServeConn(context.Background(), s3, false)
	_ = json.NewEncoder(c3).Encode(Request{Action: ActionGetUserStats, Username: "spoofed_other_user"})
	var userResp Response
	if err := json.NewDecoder(c3).Decode(&userResp); err != nil {
		t.Fatalf("decode user response: %v", err)
	}
	_ = c3.Close()
	if !userResp.OK {
		t.Fatalf("expected 2nd user request within rate limit to succeed, got %+v", userResp)
	}

	c4, s4 := net.Pipe()
	go srv.ServeConn(context.Background(), s4, false)
	var rateLimitedResp Response
	if err := json.NewDecoder(c4).Decode(&rateLimitedResp); err != nil {
		t.Fatalf("decode rate-limited response: %v", err)
	}
	_ = c4.Close()
	if rateLimitedResp.OK || !strings.Contains(rateLimitedResp.Error, "rate limit") {
		t.Fatalf("expected 3rd burst request from UID 1005 to be rate-limited, got %+v", rateLimitedResp)
	}

	// 5. Test CGI string-encoded int/bool query params unmarshal cleanly
	var req Request
	rawQueryJSON := []byte(`{"action":"get_logs","limit":"100","sync_users":"true","backup_retention":"5"}`)
	if err := json.Unmarshal(rawQueryJSON, &req); err != nil {
		t.Fatalf("expected string-encoded numeric/bool fields to coerce cleanly, got error: %v", err)
	}
	if req.Limit != 100 || !req.SyncUsers || req.BackupRetention != 5 {
		t.Fatalf("unexpected coerced request fields: %+v", req)
	}
}

type blockingUserHandler struct {
	stubHandler
	releaseCh chan struct{}
	enteredCh chan struct{}
}

func (b *blockingUserHandler) HandleUserRequest(ctx context.Context, peerUID uint32, req Request) Response {
	select {
	case b.enteredCh <- struct{}{}:
	default:
	}
	select {
	case <-b.releaseCh:
		return Response{OK: true, Data: map[string]interface{}{"peer_uid": peerUID, "action": req.Action}}
	case <-ctx.Done():
		return Response{OK: false, Error: "request context expired: " + ctx.Err().Error()}
	}
}

func TestPerUIDConcurrentConnCapRequestTimeoutAndIsDialError(t *testing.T) {
	// 1. N9b: IsDialError distinguishes socket dial failure from post-connect errors
	_, dialErr := SendRequest(context.Background(), "/nonexistent/da-limiter-missing-test.sock", Request{Action: ActionPing})
	if !IsDialError(dialErr) {
		t.Fatalf("expected IsDialError=true for missing socket, got err=%v", dialErr)
	}
	if IsDialError(errors.New("daemon timeout")) {
		t.Fatal("expected IsDialError=false for non-DialError")
	}

	// 2. N8: Per-UID concurrent user connection cap blocks 3rd simultaneous connection from UID 1005,
	// while still permitting UID 1006 to connect!
	bh := &blockingUserHandler{
		releaseCh: make(chan struct{}),
		enteredCh: make(chan struct{}, 8),
	}
	srv := NewServer("", "", bh)
	srv.MaxPerUIDUserConns = 2
	srv.UserRateLimitBurst = 50

	var currentUID uint32 = 1005
	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return currentUID, nil
	}

	openHeldConn := func() net.Conn {
		c, s := net.Pipe()
		go srv.ServeConn(context.Background(), s, false)
		_ = json.NewEncoder(c).Encode(Request{Action: ActionGetUserStats})
		<-bh.enteredCh
		return c
	}

	held1 := openHeldConn()
	held2 := openHeldConn()

	// 3rd simultaneous connection from UID 1005 must be rejected immediately
	c3, s3 := net.Pipe()
	go srv.ServeConn(context.Background(), s3, false)
	var cappedResp Response
	if err := json.NewDecoder(c3).Decode(&cappedResp); err != nil {
		t.Fatalf("decode capped response: %v", err)
	}
	_ = c3.Close()
	if cappedResp.OK || !strings.Contains(cappedResp.Error, "concurrent connections") {
		t.Fatalf("expected per-UID concurrent cap rejection (N8), got %+v", cappedResp)
	}

	// Another customer UID (1006) MUST still be able to connect while UID 1005 holds 2 slots!
	currentUID = 1006
	cOther, sOther := net.Pipe()
	go srv.ServeConn(context.Background(), sOther, false)
	_ = json.NewEncoder(cOther).Encode(Request{Action: ActionGetUserStats})
	<-bh.enteredCh

	close(bh.releaseCh)
	for _, conn := range []net.Conn{held1, held2, cOther} {
		var r Response
		_ = json.NewDecoder(conn).Decode(&r)
		_ = conn.Close()
	}

	// 3. N9a: RequestTimeout cancels slow handler context
	th := &blockingUserHandler{
		releaseCh: make(chan struct{}),
		enteredCh: make(chan struct{}, 2),
	}
	srvTimeout := NewServer("", "", th)
	srvTimeout.RequestTimeout = 60 * time.Millisecond
	srvTimeout.GetPeerUID = func(_ net.Conn) (uint32, error) { return 0, nil }

	ct, st := net.Pipe()
	go srvTimeout.ServeConn(context.Background(), st, false)
	_ = json.NewEncoder(ct).Encode(Request{Action: ActionGetUserStats})
	var timeoutResp Response
	if err := json.NewDecoder(ct).Decode(&timeoutResp); err != nil {
		t.Fatalf("decode timeout response: %v", err)
	}
	_ = ct.Close()
	if timeoutResp.OK || !strings.Contains(timeoutResp.Error, "context deadline exceeded") {
		t.Fatalf("expected per-request deadline cancellation (N9a), got %+v", timeoutResp)
	}
}
