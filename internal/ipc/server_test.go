package ipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
)

type stubHandler struct{}

func (stubHandler) HandleAdminRequest(_ context.Context, peerUID uint32, req Request) Response {
	if peerUID != 0 && peerUID != 1001 {
		return Response{OK: false, Error: "permission denied: non-admin UID"}
	}
	return Response{OK: true, Message: "admin:" + req.Action}
}

func (stubHandler) HandleUserRequest(_ context.Context, peerUID uint32, req Request) Response {
	if req.Action != ActionGetUserStats {
		return Response{OK: false, Error: "permission denied"}
	}
	return Response{OK: true, Data: map[string]interface{}{"peer_uid": peerUID}}
}

func TestServeConnAdminAndUserIsolation(t *testing.T) {
	srv := NewServer("", "", stubHandler{})
	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return 1005, nil
	}

	// 1. Test Admin Socket blocks non-admin UID (1005) via SO_PEERCRED
	c0, s0 := net.Pipe()
	go srv.ServeConn(context.Background(), s0, true)

	_ = json.NewEncoder(c0).Encode(Request{Action: ActionApplyUserLimits, Username: "vinahost"})
	var blockedAdminResp Response
	if err := json.NewDecoder(c0).Decode(&blockedAdminResp); err != nil {
		t.Fatalf("decode blocked admin response: %v", err)
	}
	_ = c0.Close()
	if blockedAdminResp.OK {
		t.Fatalf("expected non-admin UID 1005 to be rejected on admin socket, got %+v", blockedAdminResp)
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

	srv.GetPeerUID = func(_ net.Conn) (uint32, error) {
		return 1005, nil
	}

	// 2. Test User Socket blocks privileged actions
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

	// 3. Test User Socket authenticates UID via GetPeerUID
	c3, s3 := net.Pipe()
	go srv.ServeConn(context.Background(), s3, false)

	_ = json.NewEncoder(c3).Encode(Request{Action: ActionGetUserStats, Username: "spoofed_other_user"})
	var userResp Response
	if err := json.NewDecoder(c3).Decode(&userResp); err != nil {
		t.Fatalf("decode user response: %v", err)
	}
	_ = c3.Close()
	if !userResp.OK {
		t.Fatalf("expected user get_user_stats to succeed, got %+v", userResp)
	}
}
