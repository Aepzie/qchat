package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/transport"
)

// modulePath is the module whose client build-client compiles. The source
// tree is checked against it so that a wrong --source fails early instead of
// building some other program with the server's address embedded.
const modulePath = "github.com/craguS/qchat"

// clientPackage is the package build-client compiles, relative to the module
// root.
const clientPackage = "./cmd/client"

// Linker symbols set by build-client. buildcfg documents the first two.
const (
	addrSymbol    = modulePath + "/internal/buildcfg.ServerAddr"
	pinSymbol     = modulePath + "/internal/buildcfg.ServerPin"
	versionSymbol = "main.version"
)

// checksumFileName is the name of the checksum file written next to the
// binaries, in the format of sha256sum.
const checksumFileName = "SHA256SUMS"

// defaultClientTargets are the platforms build-client builds by default,
// and the only ones it accepts.
var defaultClientTargets = []clientTarget{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// versionPattern restricts --version to characters that are safe in a file
// name and inside a single -ldflags word.
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)

// clientTarget is one GOOS/GOARCH pair.
type clientTarget struct {
	goos, goarch string
}

func (t clientTarget) String() string { return t.goos + "/" + t.goarch }

// clientBuild is everything that goes into a pinned client binary. It holds
// only public values: the address clients dial and the fingerprint of the
// server's public key. Nothing derived from the private key may be added.
type clientBuild struct {
	addr    string
	pin     transport.Fingerprint
	version string
}

// cmdBuildClient builds client binaries locked to this server (see package
// buildcfg) for several platforms, and writes their SHA-256 checksums.
//
// The fingerprint comes from the certificate named in the configuration;
// the private key is never opened. The address is --server, or the first
// name in the certificate followed by the port of the listen address.
func cmdBuildClient(args []string, stdout, stderr io.Writer) error {
	fset := newFlagSet("build-client", "--config FILE [--server HOST:PORT] [--out DIR] [--targets OS/ARCH,...] [--source DIR] [--version V]", stderr)
	configPath := fset.String("config", "", "path of server.toml (required)")
	serverAddr := fset.String("server", "", "address clients dial, as host:port (default: first certificate name and the listen port)")
	outDir := fset.String("out", "qchat-clients", "directory for the binaries and "+checksumFileName)
	targetList := fset.String("targets", joinTargets(defaultClientTargets), "comma-separated GOOS/GOARCH pairs to build")
	sourceDir := fset.String("source", "", "root of the qchat source tree (default: the module containing the current directory)")
	clientVersion := fset.String("version", version, "version embedded in the clients and used in file names")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	if *configPath == "" {
		return usagef(fset, "--config is required")
	}
	if !versionPattern.MatchString(*clientVersion) {
		return usagef(fset, "--version %q must be 1-64 letters, digits, '.', '+', '_' or '-'", *clientVersion)
	}
	targets, err := parseTargets(*targetList)
	if err != nil {
		return usagef(fset, "%v", err)
	}

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	cert, err := readCertificate(cfg.TLSCert)
	if err != nil {
		return err
	}
	addr, err := publicAddress(*serverAddr, cert, cfg.Listen)
	if err != nil {
		return err
	}
	if isLoopbackHost(addr) {
		fmt.Fprintf(stderr, "%s: warning: clients will dial %s, which only works on the server machine itself; pass --server with the public address\n", programName, addr)
	}

	goTool, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("the Go toolchain is required to build clients: %w", err)
	}
	source := *sourceDir
	if source == "" {
		if source, err = defaultSourceDir(goTool); err != nil {
			return err
		}
	}
	if source, err = filepath.Abs(source); err != nil {
		return err
	}
	if err := checkSourceTree(source); err != nil {
		return err
	}
	out, err := filepath.Abs(*outDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	settings, err := goEnvSettings(goTool, source, os.Environ())
	if err != nil {
		return err
	}

	build := clientBuild{addr: addr, pin: transport.FingerprintOf(cert), version: *clientVersion}
	fmt.Fprintf(stdout, "Building qchat %s locked to %s\n", build.version, build.addr)
	printFingerprint(stdout, build.pin)

	sums := make(map[string]string, len(targets))
	for _, target := range targets {
		name := clientFileName(build.version, target)
		path := filepath.Join(out, name)
		cmd := exec.Command(goTool, goBuildArgs(build, path)...)
		cmd.Dir = source
		cmd.Env = goBuildEnv(os.Environ(), settings, target)
		cmd.Stdout = stderr
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build %s: %w", target, err)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		sums[name] = sum
		fmt.Fprintf(stdout, "  %s\n", path)
	}

	sumsPath := filepath.Join(out, checksumFileName)
	if err := os.WriteFile(sumsPath, formatChecksums(sums), 0o644); err != nil {
		return fmt.Errorf("write checksums: %w", err)
	}
	fmt.Fprintf(stdout, "  %s\n", sumsPath)
	return nil
}

// parseTargets parses a comma-separated list of GOOS/GOARCH pairs and
// rejects platforms outside defaultClientTargets and duplicates.
func parseTargets(list string) ([]clientTarget, error) {
	var targets []clientTarget
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		goos, goarch, ok := strings.Cut(field, "/")
		target := clientTarget{goos, goarch}
		if !ok || !slices.Contains(defaultClientTargets, target) {
			return nil, fmt.Errorf("unsupported target %q; supported: %s", field, joinTargets(defaultClientTargets))
		}
		if slices.Contains(targets, target) {
			return nil, fmt.Errorf("target %q listed twice", field)
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets given")
	}
	return targets, nil
}

func joinTargets(targets []clientTarget) string {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.String()
	}
	return strings.Join(names, ",")
}

// publicAddress returns the address clients dial: explicit if set, else the
// first DNS name of cert (or its first IP address if it has none) with the
// port of listen. The result is canonical as returned by
// transport.ValidateHostPort, the same check the client applies to the
// embedded value, and contains no quotes (see clientLDFlags). A wildcard
// name such as *.example.org names no host to dial, so it requires an
// explicit address.
func publicAddress(explicit string, cert *x509.Certificate, listen string) (string, error) {
	if explicit != "" {
		return validatePublicAddress(explicit)
	}
	var host string
	switch {
	case len(cert.DNSNames) > 0:
		host = cert.DNSNames[0]
		if strings.HasPrefix(host, "*.") {
			return "", fmt.Errorf("the first certificate name %q is a wildcard; pass --server host:port", host)
		}
	case len(cert.IPAddresses) > 0:
		host = cert.IPAddresses[0].String()
	default:
		return "", errors.New("the certificate names no host; pass --server host:port")
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", listen, err)
	}
	return validatePublicAddress(net.JoinHostPort(host, port))
}

// validatePublicAddress canonicalizes addr with transport.ValidateHostPort
// and rejects quotes, which the go command would interpret when it splits
// -ldflags into words.
func validatePublicAddress(addr string) (string, error) {
	canonical, err := transport.ValidateHostPort(addr)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(canonical, `'"`) {
		return "", fmt.Errorf("%w %q: quotes are not allowed", transport.ErrInvalidAddress, addr)
	}
	return canonical, nil
}

// isLoopbackHost reports whether the host of a validated address refers to
// the local machine only.
func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// clientLDFlags returns the -ldflags value for a pinned client: stripped
// symbols, an empty build ID for reproducibility, and the embedded address,
// pin and version. None of the values contains spaces or quotes (the address
// by transport.ValidateHostPort and validatePublicAddress, the version by
// versionPattern, the pin by construction), so the go command splits the
// string into exactly these words.
func clientLDFlags(build clientBuild) string {
	return strings.Join([]string{
		"-s", "-w", "-buildid=",
		"-X", addrSymbol + "=" + build.addr,
		"-X", pinSymbol + "=" + build.pin.String(),
		"-X", versionSymbol + "=" + build.version,
	}, " ")
}

// goBuildArgs returns the arguments of "go" that build one pinned client
// into output.
func goBuildArgs(build clientBuild, output string) []string {
	return []string{
		"build",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags", clientLDFlags(build),
		"-o", output,
		clientPackage,
	}
}

// pinnedGoEnv are the build settings goBuildEnv fixes, in this order,
// after the target platform. GOENV=off makes go ignore the configuration
// file written by "go env -w", which could otherwise set GOFLAGS,
// GOEXPERIMENT, GOAMD64 and the like behind the back of the environment;
// the remaining entries set the defaults explicitly.
var pinnedGoEnv = []string{
	"CGO_ENABLED=0",
	"GOWORK=off",
	"GOENV=off",
	"GOFLAGS=",
	"GOEXPERIMENT=",
	"GOAMD64=v1",
	"GOARM64=v8.0",
	"GOFIPS140=off",
}

// passThroughGoEnv are go settings that control where go finds the
// toolchain, modules and caches, but not what it compiles. Because GOENV=off
// hides values set with "go env -w", build-client reads their effective
// values with goEnvSettings and passes them explicitly. Proxy variables of
// the operating system (HTTPS_PROXY, NO_PROXY, ...) are not go settings and
// are inherited unchanged.
var passThroughGoEnv = []string{
	"GOAUTH", "GOCACHE", "GOINSECURE", "GOMODCACHE", "GONOPROXY", "GONOSUMDB",
	"GOPATH", "GOPRIVATE", "GOPROXY", "GOSUMDB", "GOTMPDIR", "GOTOOLCHAIN", "GOVCS",
}

// overriddenGoEnv lists the variables goBuildEnv removes from the inherited
// environment: those it pins or passes through, and the level variables of
// other architectures, which must not change the result either.
var overriddenGoEnv = slices.Concat(
	[]string{"GOOS", "GOARCH", "GO386", "GOARM", "GOPPC64", "GORISCV64"},
	envNames(pinnedGoEnv),
	passThroughGoEnv,
)

func envNames(entries []string) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i], _, _ = strings.Cut(entry, "=")
	}
	return names
}

// goEnvSettings returns the effective values of passThroughGoEnv, including
// those set with "go env -w", as reported by "go env -json" running in dir
// with env.
func goEnvSettings(goTool, dir string, env []string) (map[string]string, error) {
	cmd := exec.Command(goTool, append([]string{"env", "-json"}, passThroughGoEnv...)...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && len(exitErr.Stderr) > 0 {
		return nil, fmt.Errorf("go env: %w: %s", err, bytes.TrimSpace(exitErr.Stderr))
	}
	if err != nil {
		return nil, fmt.Errorf("go env: %w", err)
	}
	settings := make(map[string]string, len(passThroughGoEnv))
	if err := json.Unmarshal(output, &settings); err != nil {
		return nil, fmt.Errorf("go env: %w", err)
	}
	return settings, nil
}

// goBuildEnv returns base without the variables in overriddenGoEnv, followed
// by the non-empty settings (see goEnvSettings) in the order of
// passThroughGoEnv, the target platform and pinnedGoEnv. Everything else,
// such as PATH and HTTPS_PROXY, is kept so that go keeps working as
// configured.
func goBuildEnv(base []string, settings map[string]string, target clientTarget) []string {
	env := make([]string, 0, len(base)+len(passThroughGoEnv)+len(pinnedGoEnv)+2)
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if slices.ContainsFunc(overriddenGoEnv, func(v string) bool { return strings.EqualFold(v, name) }) {
			continue
		}
		env = append(env, entry)
	}
	for _, name := range passThroughGoEnv {
		if value := settings[name]; value != "" {
			env = append(env, name+"="+value)
		}
	}
	env = append(env, "GOOS="+target.goos, "GOARCH="+target.goarch)
	return append(env, pinnedGoEnv...)
}

// clientFileName returns qchat_<version>_<os>_<arch>, with .exe on Windows.
func clientFileName(clientVersion string, target clientTarget) string {
	name := "qchat_" + clientVersion + "_" + target.goos + "_" + target.goarch
	if target.goos == "windows" {
		name += ".exe"
	}
	return name
}

// defaultSourceDir returns the root of the module containing the current
// directory, as reported by "go env GOMOD", or the current directory when
// it is not inside a module.
func defaultSourceDir(goTool string) (string, error) {
	cmd := exec.Command(goTool, "env", "GOMOD")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(output))
	if gomod == "" || gomod == os.DevNull {
		return os.Getwd()
	}
	return filepath.Dir(gomod), nil
}

// checkSourceTree verifies that dir is the root of the qchat module and
// contains the client package.
func checkSourceTree(dir string) error {
	content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return fmt.Errorf("source tree %s: %w (pass --source with the qchat source directory)", dir, err)
	}
	if goModModule(content) != modulePath {
		return fmt.Errorf("source tree %s is not the %s module (pass --source with the qchat source directory)", dir, modulePath)
	}
	if info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(clientPackage))); err != nil || !info.IsDir() {
		return fmt.Errorf("source tree %s has no %s directory", dir, clientPackage)
	}
	return nil
}

// goModModule returns the module path declared in a go.mod file.
func goModModule(content []byte) string {
	for _, line := range strings.Split(string(content), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			rest, _, _ = strings.Cut(rest, "//")
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// formatChecksums renders sums (file name to hex digest) in the format of
// sha256sum, sorted by name, so "sha256sum -c SHA256SUMS" verifies them.
func formatChecksums(sums map[string]string) []byte {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[name], name)
	}
	return b.Bytes()
}
