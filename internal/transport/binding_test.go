package transport

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/coder/websocket"
)

// dialBinding opens a connection to ts and returns the client and server
// side channel bindings of it.
func dialBinding(t *testing.T, ts *testServer) (client, server []byte) {
	t.Helper()
	conn, state, err := DialWithState(testContext(t), ts.addr, ts.pin, DialOptions{})
	if err != nil {
		t.Fatalf("DialWithState: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	client, err = AuthBinding(&state)
	if err != nil {
		t.Fatalf("client AuthBinding: %v", err)
	}
	serverState := <-ts.tlsStates
	server, err = AuthBinding(&serverState)
	if err != nil {
		t.Fatalf("server AuthBinding: %v", err)
	}
	return client, server
}

func TestAuthBindingMatchesAcrossConnection(t *testing.T) {
	ts := startTestServer(t, 0)
	firstClient, firstServer := dialBinding(t, ts)
	if len(firstClient) != AuthBindingSize {
		t.Fatalf("binding is %d bytes, want %d", len(firstClient), AuthBindingSize)
	}
	if !bytes.Equal(firstClient, firstServer) {
		t.Fatal("client and server derive different bindings for one connection")
	}
	secondClient, secondServer := dialBinding(t, ts)
	if !bytes.Equal(secondClient, secondServer) {
		t.Fatal("client and server derive different bindings for one connection")
	}
	if bytes.Equal(firstClient, secondClient) {
		t.Fatal("two connections share a channel binding")
	}
}

func TestAuthBindingRejectsUnusableState(t *testing.T) {
	cases := map[string]*tls.ConnectionState{
		"nil":               nil,
		"handshake pending": {Version: tls.VersionTLS13},
		"TLS 1.2":           {Version: tls.VersionTLS12, HandshakeComplete: true},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			if binding, err := AuthBinding(state); err == nil {
				t.Errorf("AuthBinding succeeded with %d bytes", len(binding))
			}
		})
	}
}
