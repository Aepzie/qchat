package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/transport"
)

func TestPrekeyRequestsDeliveryAndAck(t *testing.T) {
	a := newFakeAuth()
	acks := make(chan uint64, 4)
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		if writeFrame(ctx, conn, protocol.TypeDeliver, 0, protocol.Deliver{From: idOf(9), Payload: []byte("queued"), QueueID: 41}) != nil {
			return
		}
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			switch f.Type {
			case protocol.TypePrekeyUpload:
				up, err := protocol.DecodeBody[protocol.PrekeyUpload](f, protocol.TypePrekeyUpload)
				if err != nil {
					t.Errorf("PrekeyUpload: %v", err)
					return false
				}
				status := protocol.PrekeyStatus{OneTimeRemaining: uint32(len(up.OneTimePrekeys)), SignedPrekeyExpires: int64(len(up.SignedPrekey))}
				return writeFrame(ctx, conn, protocol.TypePrekeyStatus, f.ID, status) == nil
			case protocol.TypePrekeyRequest:
				req, err := protocol.DecodeBody[protocol.PrekeyRequest](f, protocol.TypePrekeyRequest)
				if err != nil {
					t.Errorf("PrekeyRequest: %v", err)
					return false
				}
				if bytes.Equal(req.ID, idOf(0)) {
					return writeFrame(ctx, conn, protocol.TypeError, f.ID, protocol.ErrorBody{Code: protocol.ErrCodeNotFound}) == nil
				}
				resp := protocol.PrekeyResponse{Bundle: req.ID, SignedPrekey: []byte("spk"), OneTimePrekey: []byte("opk")}
				return writeFrame(ctx, conn, protocol.TypePrekeyResponse, f.ID, resp) == nil
			case protocol.TypeAck:
				ack, err := protocol.DecodeBody[protocol.Ack](f, protocol.TypeAck)
				if err != nil {
					t.Errorf("Ack: %v", err)
					return false
				}
				acks <- ack.QueueID
				return true
			case protocol.TypeSend:
				return writeFrame(ctx, conn, protocol.TypeSendResult, f.ID, protocol.SendResult{Status: protocol.SendAccepted}) == nil
			default:
				t.Errorf("unexpected %v frame", f.Type)
				return false
			}
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	seen := waitFor(t, s, "Delivery", func(ev Event) bool { _, ok := ev.(Delivery); return ok })
	d := seen[len(seen)-1].(Delivery)
	if d.QueueID != 41 || string(d.Payload) != "queued" || d.From != [32]byte(idOf(9)) {
		t.Fatalf("Delivery = %+v", d)
	}
	ctx := requestCtx(t)

	if err := s.Ack(d.QueueID); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	select {
	case got := <-acks:
		if got != 41 {
			t.Fatalf("relay received Ack for %d, want 41", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relay received no Ack")
	}

	f, err := s.Request(ctx, protocol.TypePrekeyUpload, protocol.PrekeyUpload{SignedPrekey: []byte("spk!"), OneTimePrekeys: [][]byte{[]byte("a"), []byte("b")}})
	if err != nil {
		t.Fatalf("PrekeyUpload: %v", err)
	}
	status, err := protocol.DecodeBody[protocol.PrekeyStatus](f, protocol.TypePrekeyStatus)
	if err != nil || status.OneTimeRemaining != 2 || status.SignedPrekeyExpires != 4 {
		t.Fatalf("PrekeyStatus = %+v, %v", status, err)
	}
	if f, err = s.Request(ctx, protocol.TypePrekeyUpload, protocol.PrekeyUpload{}); err != nil {
		t.Fatalf("empty PrekeyUpload: %v", err)
	}
	if status, err = protocol.DecodeBody[protocol.PrekeyStatus](f, protocol.TypePrekeyStatus); err != nil || status != (protocol.PrekeyStatus{}) {
		t.Fatalf("PrekeyStatus for an empty upload = %+v, %v", status, err)
	}

	f, err = s.Request(ctx, protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: idOf(5)})
	if err != nil {
		t.Fatalf("PrekeyRequest: %v", err)
	}
	resp, err := protocol.DecodeBody[protocol.PrekeyResponse](f, protocol.TypePrekeyResponse)
	if err != nil || !bytes.Equal(resp.Bundle, idOf(5)) || string(resp.SignedPrekey) != "spk" || string(resp.OneTimePrekey) != "opk" {
		t.Fatalf("PrekeyResponse = %+v, %v", resp, err)
	}
	_, err = s.Request(ctx, protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: idOf(0)})
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("PrekeyRequest for unknown ID = %v, want NotFound", err)
	}

	f, err = s.Request(ctx, protocol.TypeSend, protocol.Send{To: idOf(5), Payload: []byte("x")})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if result, err := protocol.DecodeBody[protocol.SendResult](f, protocol.TypeSendResult); err != nil || result.Status != protocol.SendAccepted {
		t.Fatalf("SendResult = %+v, %v", result, err)
	}
	if _, err := s.Request(ctx, protocol.TypeAck, protocol.Ack{QueueID: 1}); err == nil {
		t.Fatal("Request accepted an Ack, which has no response")
	}
}

func TestAckRequiresAuthenticatedConnection(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	s := newTestSession(t, Options{Addr: "127.0.0.1:1", Pin: pin, Auth: newFakeAuth()})
	if err := s.Ack(1); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Ack while disconnected = %v, want ErrNotConnected", err)
	}

	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if welcome(ctx, t, conn) {
			servePongs(ctx, conn, 0)
		}
	})
	plain := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	runSession(t, plain)
	waitFor(t, plain, "Connected", isState(Connected))
	if err := plain.Ack(1); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Ack without Auth = %v, want ErrNotConnected", err)
	}
}
