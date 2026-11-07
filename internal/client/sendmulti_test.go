package client

import (
	"testing"

	"github.com/craguS/qchat/internal/protocol"
)

func TestSendMultiIsARequest(t *testing.T) {
	want, ok := responseType(protocol.TypeSendMulti)
	if !ok || want != protocol.TypeSendMultiResult {
		t.Fatalf("responseType(SendMulti) = %v, %v", want, ok)
	}
	if want, ok := responseType(protocol.TypeSend); !ok || want != protocol.TypeSendResult {
		t.Fatalf("responseType(Send) = %v, %v", want, ok)
	}
}
