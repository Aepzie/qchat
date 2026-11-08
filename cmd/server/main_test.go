package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/transport"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

var pinPattern = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

func initDataDir(t *testing.T, extra ...string) (dir, pin string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "data")
	code, stdout, stderr := runCLI(t, append([]string{"init", "--data-dir", dir}, extra...)...)
	if code != 0 {
		t.Fatalf("init exit %d: %s", code, stderr)
	}
	pin = pinPattern.FindString(stdout)
	if pin == "" {
		t.Fatalf("init printed no fingerprint:\n%s", stdout)
	}
	return dir, pin
}

func TestInitCreatesIdentityAndConfig(t *testing.T) {
	dir, pin := initDataDir(t, "--host", "chat.example.org", "--host", "192.0.2.7", "--listen", "127.0.0.1:7999")

	for _, name := range []string{keyFileName, certFileName, configFileName, server.DefaultDatabase} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", name, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("data directory has mode %04o, want 0700", info.Mode().Perm())
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".*tmp-*")); len(leftovers) > 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}

	cfg, err := server.LoadConfig(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatalf("generated config does not load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:7999" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	cert, err := transport.LoadServerCertificate(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		t.Fatalf("generated identity does not load: %v", err)
	}
	got, err := transport.FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != pin {
		t.Fatalf("printed pin %s, identity has %s", pin, got)
	}
	if cert.Leaf.DNSNames[0] != "chat.example.org" || len(cert.Leaf.IPAddresses) != 1 {
		t.Errorf("SANs = %v %v", cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
	}

	_, stdout, _ := runCLI(t, "fingerprint", "--data-dir", dir)
	if !strings.Contains(stdout, pin) || !strings.Contains(stdout, got.Grouped()) {
		t.Errorf("fingerprint output lacks both forms:\n%s", stdout)
	}
}

func TestInitPrintsClientCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	code, stdout, stderr := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("init exit %d: %s", code, stderr)
	}
	pin := pinPattern.FindString(stdout)
	if want := "qchat --server localhost:7443 --pin " + pin; !strings.Contains(stdout, want) {
		t.Errorf("output lacks %q:\n%s", want, stdout)
	}

	dir6 := filepath.Join(t.TempDir(), "d6")
	_, stdout, _ = runCLI(t, "init", "--data-dir", dir6, "--host", "2001:db8::1", "--listen", "[::]:8443")
	if !strings.Contains(stdout, "qchat --server [2001:db8::1]:8443 --pin sha256:") {
		t.Errorf("IPv6 client command wrong:\n%s", stdout)
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	dir, pin := initDataDir(t)
	keyBefore, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCLI(t, "init", "--data-dir", dir)
	if code != 1 || !strings.Contains(stderr, "--force") {
		t.Fatalf("second init: exit %d, stderr %q", code, stderr)
	}
	keyAfter, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("key changed although init refused")
	}

	if err := os.Remove(filepath.Join(dir, keyFileName)); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "init", "--data-dir", dir); code != 1 {
		t.Fatalf("init over an existing config: exit %d, want 1", code)
	}

	code, stdout, stderr := runCLI(t, "init", "--data-dir", dir, "--force")
	if code != 0 {
		t.Fatalf("init --force exit %d: %s", code, stderr)
	}
	if newPin := pinPattern.FindString(stdout); newPin == "" || newPin == pin {
		t.Fatalf("init --force did not create a new identity (old %s, new %s)", pin, newPin)
	}
}

func TestInitErrors(t *testing.T) {
	if code, _, stderr := runCLI(t, "init"); code != 2 || !strings.Contains(stderr, "--data-dir") {
		t.Errorf("init without --data-dir: exit %d, stderr %q", code, stderr)
	}
	dir := filepath.Join(t.TempDir(), "bad")
	if code, _, _ := runCLI(t, "init", "--data-dir", dir, "--listen", "nonsense"); code != 1 {
		t.Errorf("init with bad --listen: exit %d, want 1", code)
	}
	if code, _, _ := runCLI(t, "init", "--data-dir", dir, "--host", "bad host!"); code != 1 {
		t.Errorf("init with bad --host: exit %d, want 1", code)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
		t.Error("key written although init failed")
	}
	if code, _, _ := runCLI(t, "init", "--data-dir", dir, "extra"); code != 2 {
		t.Errorf("init with positional argument: exit %d, want 2", code)
	}
	if code, _, _ := runCLI(t, "init", "--bogus"); code != 2 {
		t.Errorf("init with unknown flag: exit %d, want 2", code)
	}
}

func TestFingerprintCommand(t *testing.T) {
	dir, pin := initDataDir(t)
	for _, args := range [][]string{
		{"fingerprint", "--data-dir", dir},
		{"fingerprint", "--config", filepath.Join(dir, configFileName)},
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 0 || !strings.Contains(stdout, pin) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
	for _, args := range [][]string{
		{"fingerprint"},
		{"fingerprint", "--data-dir", dir, "--config", filepath.Join(dir, configFileName)},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "fingerprint", "--data-dir", t.TempDir()); code != 1 {
		t.Errorf("fingerprint of empty directory: exit %d, want 1", code)
	}
}

func TestCertificateFingerprintSkipsOtherBlocks(t *testing.T) {
	dir, pin := initDataDir(t)
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName))
	if err != nil {
		t.Fatal(err)
	}
	mixed := append(pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("x")}), certPEM...)
	path := filepath.Join(t.TempDir(), "mixed.crt")
	if err := os.WriteFile(path, mixed, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := certificateFingerprint(path)
	if err != nil || got.String() != pin {
		t.Fatalf("certificateFingerprint = %s, %v; want %s", got, err, pin)
	}

	block, _ := pem.Decode(certPEM)
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateFingerprint(path); err == nil {
		t.Fatal("broken certificate accepted")
	}
}

func TestVersionHelpAndUnknown(t *testing.T) {
	if code, stdout, _ := runCLI(t, "version"); code != 0 || stdout != "qchat-server dev\n" {
		t.Errorf("version: exit %d, stdout %q", code, stdout)
	}
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"frobnicate"}, {"build-client"}} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "Usage: qchat-server") || !strings.Contains(stderr, "build-client") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestRunCommandErrors(t *testing.T) {
	if code, _, _ := runCLI(t, "run"); code != 2 {
		t.Errorf("run without --config: exit %d, want 2", code)
	}
	code, _, stderr := runCLI(t, "run", "--config", filepath.Join(t.TempDir(), "absent.toml"))
	if code != 1 || !strings.HasPrefix(stderr, "qchat-server: ") {
		t.Errorf("run with missing config: exit %d, stderr %q", code, stderr)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var portPattern = regexp.MustCompile(`msg="server listening" port=(\d+)`)

// TestServeConfigEndToEnd initialises a data directory, serves it and
// completes a protocol handshake with the fingerprint printed by init.
func TestServeConfigEndToEnd(t *testing.T) {
	dir, pinText := initDataDir(t, "--listen", "127.0.0.1:0")
	pin, err := transport.ParseFingerprint(pinText)
	if err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveConfig(ctx, filepath.Join(dir, configFileName), logs) }()

	var port string
	deadline := time.Now().Add(10 * time.Second)
	for port == "" {
		if m := portPattern.FindStringSubmatch(logs.String()); m != nil {
			port = m[1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start; log:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	conn, err := transport.Dial(dialCtx, net.JoinHostPort("127.0.0.1", port), pin, transport.DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	frame, err := protocol.NewFrame(protocol.TypeHello, 1, protocol.ClientHello())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(dialCtx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	_, reply, err := conn.Read(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	welcomeFrame, err := protocol.Decode(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeBody[protocol.Welcome](welcomeFrame, protocol.TypeWelcome); err != nil {
		t.Fatalf("expected Welcome: %v", err)
	}

	cancel()
	_, _, _ = conn.Read(dialCtx)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveConfig: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serveConfig did not return after cancellation")
	}
	output := logs.String()
	if !strings.Contains(output, pinText) || !strings.Contains(output, "server stopped") {
		t.Errorf("unexpected log:\n%s", output)
	}
	if strings.Contains(output, "127.0.0.1") {
		t.Errorf("log contains a client address:\n%s", output)
	}
}
