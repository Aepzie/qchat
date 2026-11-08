package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Aepzie/qchat/internal/server"
	"github.com/Aepzie/qchat/internal/transport"
)

func testCertificate(t *testing.T, hosts ...string) *x509.Certificate {
	t.Helper()
	certPEM, _, err := transport.GenerateServerIdentity(hosts)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestParseTargets(t *testing.T) {
	all, err := parseTargets(joinTargets(defaultClientTargets))
	if err != nil || !slices.Equal(all, defaultClientTargets) {
		t.Fatalf("default targets: %v, %v", all, err)
	}
	some, err := parseTargets(" windows/arm64, linux/amd64 ,")
	if err != nil || !slices.Equal(some, []clientTarget{{"windows", "arm64"}, {"linux", "amd64"}}) {
		t.Fatalf("subset: %v, %v", some, err)
	}
	for _, bad := range []string{"", ",", "linux", "linux/amd64/v3", "freebsd/amd64", "js/wasm", "Linux/amd64", "linux/amd64,linux/amd64"} {
		if got, err := parseTargets(bad); err == nil {
			t.Errorf("parseTargets(%q) = %v, want error", bad, got)
		}
	}
}

func TestPublicAddress(t *testing.T) {
	named := testCertificate(t, "chat.example.org", "192.0.2.7")
	ipOnly := testCertificate(t, "2001:db8::1")
	cases := []struct {
		explicit string
		cert     *x509.Certificate
		listen   string
		want     string
	}{
		{"", named, "0.0.0.0:7443", "chat.example.org:7443"},
		{"", named, ":8443", "chat.example.org:8443"},
		{"", ipOnly, "[::]:7443", "[2001:db8::1]:7443"},
		{"relay.example.net:0443", named, "0.0.0.0:7443", "relay.example.net:443"},
		{"198.51.100.4:9000", ipOnly, "0.0.0.0:7443", "198.51.100.4:9000"},
	}
	for _, c := range cases {
		got, err := publicAddress(c.explicit, c.cert, c.listen)
		if err != nil || got != c.want {
			t.Errorf("publicAddress(%q, %v, %q) = %q, %v; want %q", c.explicit, c.cert.DNSNames, c.listen, got, err, c.want)
		}
	}
	for _, bad := range []string{"chat.example.org", "chat.example.org:0", "user@chat.example.org:443", "chat example.org:443", "a/b:443"} {
		if _, err := publicAddress(bad, named, "0.0.0.0:7443"); !errors.Is(err, transport.ErrInvalidAddress) {
			t.Errorf("publicAddress(%q): err = %v, want ErrInvalidAddress", bad, err)
		}
	}
	if _, err := publicAddress("", named, "no-port"); err == nil {
		t.Error("listen address without port accepted")
	}
	if _, err := publicAddress("", &x509.Certificate{}, "0.0.0.0:7443"); err == nil {
		t.Error("certificate without names accepted")
	}
	wildcard := &x509.Certificate{DNSNames: []string{"*.example.org", "chat.example.org"}}
	if got, err := publicAddress("", wildcard, "0.0.0.0:7443"); err == nil || !strings.Contains(err.Error(), "--server") {
		t.Errorf("wildcard certificate name: %q, %v; want an error asking for --server", got, err)
	}
	if got, err := publicAddress("chat.example.org:7443", wildcard, "0.0.0.0:7443"); err != nil || got != "chat.example.org:7443" {
		t.Errorf("explicit address with wildcard certificate: %q, %v", got, err)
	}
	for _, quoted := range []string{`chat"example.org:443`, `chat'example.org:443`} {
		if _, err := publicAddress(quoted, named, "0.0.0.0:7443"); !errors.Is(err, transport.ErrInvalidAddress) {
			t.Errorf("publicAddress(%q): err = %v, want ErrInvalidAddress", quoted, err)
		}
	}
	quotedName := &x509.Certificate{DNSNames: []string{`chat"x.example.org`}}
	if _, err := publicAddress("", quotedName, "0.0.0.0:7443"); !errors.Is(err, transport.ErrInvalidAddress) {
		t.Errorf("quoted certificate name: err = %v, want ErrInvalidAddress", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for addr, want := range map[string]bool{
		"localhost:7443":        true,
		"LOCALHOST.:7443":       true,
		"app.localhost:7443":    true,
		"127.0.0.1:7443":        true,
		"[::1]:7443":            true,
		"chat.example.org:7443": false,
		"192.0.2.7:7443":        false,
		"localhost.example:1":   false,
	} {
		if got := isLoopbackHost(addr); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestGoBuildArgs(t *testing.T) {
	pin, err := transport.ParseFingerprint("sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatal(err)
	}
	build := clientBuild{addr: "chat.example.org:7443", pin: pin, version: "v1.2.3"}
	got := goBuildArgs(build, "/out/qchat")
	want := []string{
		"build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -buildid=" +
			" -X github.com/Aepzie/qchat/internal/buildcfg.ServerAddr=chat.example.org:7443" +
			" -X github.com/Aepzie/qchat/internal/buildcfg.ServerPin=sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
			" -X main.version=v1.2.3",
		"-o", "/out/qchat",
		"./cmd/client",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("goBuildArgs =\n%q\nwant\n%q", got, want)
	}
}

// TestBuildEmbedsOnlyPublicValues checks that the go command line built for a
// real server identity contains the address and fingerprint and nothing of
// the private key.
func TestBuildEmbedsOnlyPublicValues(t *testing.T) {
	dir, pin := initDataDir(t, "--host", "chat.example.org")
	cfg, err := server.LoadConfig(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := readCertificate(cfg.TLSCert)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := publicAddress("", cert, cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	build := clientBuild{addr: addr, pin: transport.FingerprintOf(cert), version: "v1.0.0"}
	args := goBuildArgs(build, filepath.Join(t.TempDir(), "qchat"))

	var symbols []string
	words := strings.Fields(clientLDFlags(build))
	for i, word := range words {
		if word == "-X" && i+1 < len(words) {
			symbols = append(symbols, words[i+1])
		}
	}
	wantSymbols := []string{addrSymbol + "=" + addr, pinSymbol + "=" + pin, versionSymbol + "=v1.0.0"}
	if !slices.Equal(symbols, wantSymbols) {
		t.Fatalf("embedded values = %q, want %q", symbols, wantSymbols)
	}

	assertNoKeyMaterial(t, []byte(strings.Join(args, "\x00")), cfg.TLSKey)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, cfg.TLSKey) || strings.Contains(joined, "PRIVATE KEY") {
		t.Error("build arguments mention the private key")
	}
}

// assertNoKeyMaterial fails if haystack contains the PEM text, the DER
// encoding or the Ed25519 seed of the private key in keyPath.
func assertNoKeyMaterial(t *testing.T, haystack []byte, keyPath string) {
	t.Helper()
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("no PEM block in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{block.Bytes}
	if edKey, ok := key.(ed25519.PrivateKey); ok {
		secrets = append(secrets, edKey.Seed())
	}
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
			secrets = append(secrets, []byte(line))
		}
	}
	for _, secret := range secrets {
		if bytes.Contains(haystack, secret) {
			t.Fatalf("private key material (%d bytes) found", len(secret))
		}
	}
}

func TestGoBuildEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"=C:=C:\\work",
		"GOFLAGS=-ldflags=-X=main.version=evil",
		"goos=plan9",
		"GOARCH=386",
		"CGO_ENABLED=1",
		"GOAMD64=v3",
		"GOARM64=v9.0",
		"GOEXPERIMENT=boringcrypto",
		"GOFIPS140=latest",
		"GOENV=/elsewhere/go.env",
		"GOWORK=/elsewhere/go.work",
		"GOPROXY=off",
		"HTTPS_PROXY=http://proxy.example:3128",
		"GOOSE=kept",
	}
	settings := map[string]string{
		"GOPROXY":    "https://proxy.example",
		"GOMODCACHE": "/cache/mod",
		"GOSUMDB":    "",
		"GOFLAGS":    "-race",
	}
	got := goBuildEnv(base, settings, clientTarget{"darwin", "arm64"})
	want := []string{
		"PATH=/usr/bin",
		"=C:=C:\\work",
		"HTTPS_PROXY=http://proxy.example:3128",
		"GOOSE=kept",
		"GOMODCACHE=/cache/mod",
		"GOPROXY=https://proxy.example",
		"GOOS=darwin",
		"GOARCH=arm64",
		"CGO_ENABLED=0",
		"GOWORK=off",
		"GOENV=off",
		"GOFLAGS=",
		"GOEXPERIMENT=",
		"GOAMD64=v1",
		"GOARM64=v8.0",
		"GOFIPS140=off",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("goBuildEnv =\n%q\nwant\n%q", got, want)
	}
}

// TestGoBuildEnvIgnoresGoEnvFile checks against the real go command that
// settings stored with "go env -w" cannot change the build, while the
// module proxy configured there still reaches it.
func TestGoBuildEnvIgnoresGoEnvFile(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not in PATH")
	}
	envFile := filepath.Join(t.TempDir(), "go.env")
	content := "GOFLAGS=-tags=evil\nGOAMD64=v4\nGOPROXY=https://proxy.example.invalid\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	base := append(slices.DeleteFunc(os.Environ(), func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		return slices.ContainsFunc(overriddenGoEnv, func(v string) bool { return strings.EqualFold(v, name) })
	}), "GOENV="+envFile)

	settings, err := goEnvSettings(goTool, ".", base)
	if err != nil {
		t.Fatal(err)
	}
	if settings["GOPROXY"] != "https://proxy.example.invalid" {
		t.Errorf("GOPROXY from the go env file = %q, want it passed through", settings["GOPROXY"])
	}
	cmd := exec.Command(goTool, "env", "-json", "GOFLAGS", "GOAMD64", "GOPROXY")
	cmd.Env = goBuildEnv(base, settings, clientTarget{"linux", "amd64"})
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	var effective map[string]string
	if err := json.Unmarshal(output, &effective); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GOFLAGS": "",
		"GOAMD64": "v1",
		"GOPROXY": "https://proxy.example.invalid",
	}
	for name, value := range want {
		if effective[name] != value {
			t.Errorf("effective %s = %q, want %q", name, effective[name], value)
		}
	}
}

func TestClientFileNameAndChecksums(t *testing.T) {
	if got := clientFileName("v1.0.0", clientTarget{"windows", "arm64"}); got != "qchat_v1.0.0_windows_arm64.exe" {
		t.Errorf("windows name = %q", got)
	}
	if got := clientFileName("1.0.0", clientTarget{"darwin", "amd64"}); got != "qchat_1.0.0_darwin_amd64" {
		t.Errorf("darwin name = %q", got)
	}
	got := string(formatChecksums(map[string]string{"b": "22", "a": "11"}))
	if got != "11  a\n22  b\n" {
		t.Errorf("formatChecksums = %q", got)
	}
}

func TestGoModModule(t *testing.T) {
	for content, want := range map[string]string{
		"module github.com/Aepzie/qchat\n\ngo 1.27.3\n":        modulePath,
		"// header\nmodule \"github.com/Aepzie/qchat\" // x\n": modulePath,
		"modules example.com/x\n":                              "",
		"go 1.27\n":                                            "",
	} {
		if got := goModModule([]byte(content)); got != want {
			t.Errorf("goModModule(%q) = %q, want %q", content, got, want)
		}
	}
}

func TestBuildClientUsageErrors(t *testing.T) {
	dir, _ := initDataDir(t)
	config := filepath.Join(dir, configFileName)
	for _, args := range [][]string{
		{"build-client"},
		{"build-client", "--config", config, "extra"},
		{"build-client", "--config", config, "--version", "1 0"},
		{"build-client", "--config", config, "--version", "../x"},
		{"build-client", "--config", config, "--targets", "plan9/amd64"},
	} {
		if code, stdout, _ := runCLI(t, args...); code != 2 || stdout != "" {
			t.Errorf("%q: exit %d, stdout %q; want 2", args, code, stdout)
		}
	}
	code, _, stderr := runCLI(t, "build-client", "--config", config, "--server", "chat.example.org")
	if code != 1 || !strings.Contains(stderr, "invalid") {
		t.Errorf("bad --server: exit %d, stderr %q", code, stderr)
	}
}

// TestBuildClientNeverReadsKey removes the private key and checks that
// build-client gets past loading the configuration and certificate; it
// then stops at the deliberately wrong source tree.
func TestBuildClientNeverReadsKey(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not in PATH")
	}
	dir, _ := initDataDir(t, "--host", "chat.example.org")
	if err := os.Remove(filepath.Join(dir, keyFileName)); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "build-client", "--config", filepath.Join(dir, configFileName),
		"--source", t.TempDir(), "--out", t.TempDir())
	if code != 1 || !strings.Contains(stderr, "source tree") {
		t.Fatalf("exit %d, stderr %q; want a source tree error", code, stderr)
	}
}

func TestCheckOutDirRefusesLinksAndFiles(t *testing.T) {
	base := t.TempDir()
	if err := checkOutDir(base); err != nil {
		t.Fatalf("plain directory: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkOutDir(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("regular file: err = %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	if err := checkOutDir(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symbolic link: err = %v", err)
	}
}

// TestBuildClientRefusesSymlinkedOut checks that build-client stops before
// building anything when --out is a symbolic link.
func TestBuildClientRefusesSymlinkedOut(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not in PATH")
	}
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "out")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	dir, _ := initDataDir(t, "--host", "chat.example.org")
	code, _, stderr := runCLI(t, "build-client", "--config", filepath.Join(dir, configFileName),
		"--source", source, "--out", link, "--targets", "linux/amd64")
	if code != 1 || !strings.Contains(stderr, "symbolic link") {
		t.Fatalf("exit %d, stderr %q; want a symbolic link error", code, stderr)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("link target holds %v (%v), want nothing", entries, err)
	}
}

// TestBuildClientReproducible builds the client for the host platform from
// this repository twice and checks that both builds are byte-identical, that
// SHA256SUMS matches, that the binary carries the address and fingerprint
// and no private key material, and that it reports itself as locked.
func TestBuildClientReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the client twice")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not in PATH")
	}
	host := clientTarget{runtime.GOOS, runtime.GOARCH}
	if !slices.Contains(defaultClientTargets, host) {
		t.Skipf("host platform %s is not a client target", host)
	}
	dir, pin := initDataDir(t, "--host", "chat.example.org", "--listen", "127.0.0.1:7999")
	config := filepath.Join(dir, configFileName)
	const testVersion = "v0.0.0-test"
	name := clientFileName(testVersion, host)

	decoy := filepath.Join(t.TempDir(), "decoy")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}

	var binaries [][]byte
	for range 2 {
		out := t.TempDir()
		linked := len(binaries) == 0 && os.Symlink(decoy, filepath.Join(out, checksumFileName)) == nil
		code, stdout, stderr := runCLI(t, "build-client", "--config", config, "--out", out,
			"--targets", host.String(), "--version", testVersion)
		if code != 0 {
			t.Fatalf("build-client exit %d:\n%s\n%s", code, stdout, stderr)
		}
		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".build-") {
				t.Errorf("staging directory %s left behind", entry.Name())
			}
		}
		if linked {
			if content, err := os.ReadFile(decoy); err != nil || string(content) != "decoy" {
				t.Errorf("%s written through a symbolic link: %q, %v", checksumFileName, content, err)
			}
			if info, err := os.Lstat(filepath.Join(out, checksumFileName)); err != nil || !info.Mode().IsRegular() {
				t.Errorf("%s is not a regular file after build-client: %v", checksumFileName, err)
			}
		}
		if !strings.Contains(stdout, pin) {
			t.Errorf("build-client did not print the fingerprint:\n%s", stdout)
		}
		binary, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		sums, err := os.ReadFile(filepath.Join(out, checksumFileName))
		if err != nil {
			t.Fatal(err)
		}
		sum, err := fileSHA256(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if want := sum + "  " + name + "\n"; string(sums) != want {
			t.Errorf("%s = %q, want %q", checksumFileName, sums, want)
		}
		binaries = append(binaries, binary)

		if len(binaries) == 1 {
			cmd := exec.Command(filepath.Join(out, name), "--version")
			versionOut, err := cmd.Output()
			if err != nil {
				t.Fatalf("run built client: %v", err)
			}
			want := "qchat " + testVersion + " (locked to chat.example.org:7999)"
			if got := strings.TrimSpace(string(versionOut)); got != want {
				t.Errorf("built client --version = %q, want %q", got, want)
			}
		}
	}

	if !bytes.Equal(binaries[0], binaries[1]) {
		t.Fatal("two builds from the same source and configuration differ")
	}
	for _, public := range []string{"chat.example.org:7999", pin} {
		if !bytes.Contains(binaries[0], []byte(public)) {
			t.Errorf("binary does not contain %q", public)
		}
	}
	cfg, err := server.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	assertNoKeyMaterial(t, binaries[0], cfg.TLSKey)
}
