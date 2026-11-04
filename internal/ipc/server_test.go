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
