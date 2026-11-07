package transport

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// startNotFoundServer runs NewHTTPServer with a handler that answers every
// request with 404 and returns its address and certificate pin.
func startNotFoundServer(t *testing.T) (string, Fingerprint) {
	t.Helper()
	certPEM, keyPEM, err := GenerateServerIdentity([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(ln.Addr().String(), http.NotFoundHandler(), ServerTLSConfig(cert))
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), pin
}

// TestNewHTTPServerClosesAfterOneRequest checks that keep-alives are off:
// after the first response the server closes the connection, so a second
// request on the same connection gets no answer.
func TestNewHTTPServerClosesAfterOneRequest(t *testing.T) {
	addr, pin := startNotFoundServer(t)
	conn, err := tls.Dial("tcp", addr, ClientTLSConfig(pin))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	const request = "GET /nothing HTTP/1.1\r\nHost: qchat\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if !resp.Close {
		t.Error("first response does not announce Connection: close")
	}

	_, _ = io.WriteString(conn, request)
	second, err := http.ReadResponse(reader, nil)
	if err == nil {
		second.Body.Close()
		t.Fatal("server answered a second request on the same connection")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection stayed open after the first response: %v", err)
	}
}
