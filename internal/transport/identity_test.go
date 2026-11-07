package transport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeIdentity stores PEM files in a temporary directory and returns their
// paths.
func writeIdentity(t *testing.T, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// selfSignedPEM creates a minimal self-signed certificate for an arbitrary
// key type, used to test which keys LoadServerCertificate accepts.
func selfSignedPEM(t *testing.T, signer crypto.Signer) (certPEM, keyPEM []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

func TestGenerateAndLoadServerIdentity(t *testing.T) {
	certPEM, keyPEM, err := GenerateServerIdentity([]string{
		"chat.example.org", "CHAT.example.org.", "127.0.0.1", "::1", "[::1]", "", "  ", "x.onion",
	})
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM block type = %v, want PRIVATE KEY", block)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("key is not PKCS#8: %v", err)
	}

	certPath, keyPath := writeIdentity(t, certPEM, keyPEM)
	cert, err := LoadServerCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.PrivateKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("private key type %T, want ed25519.PrivateKey", cert.PrivateKey)
	}

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Leaf not populated")
	}
	if leaf.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("public key algorithm %v, want Ed25519", leaf.PublicKeyAlgorithm)
	}
	if got := leaf.DNSNames; len(got) != 2 || got[0] != "chat.example.org" || got[1] != "x.onion" {
		t.Fatalf("DNSNames = %v", got)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1 and ::1", leaf.IPAddresses)
	}
	if leaf.IsCA {
		t.Fatal("server certificate must not be a CA")
	}
	if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial number %v out of range", leaf.SerialNumber)
	}
	if leaf.NotAfter.Year() != 9999 {
		t.Fatalf("NotAfter = %v, want year 9999", leaf.NotAfter)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("certificate is not validly self-signed: %v", err)
	}

	fromLeaf := FingerprintOf(leaf)
	fromTLS, err := FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.Leaf = nil
	parsed, err := FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !fromLeaf.Equal(fromTLS) || !fromLeaf.Equal(parsed) || fromLeaf.IsZero() {
		t.Fatalf("fingerprints disagree: %s %s %s", fromLeaf, fromTLS, parsed)
	}

	again, err := LoadServerCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := FingerprintOfTLS(again); !fp.Equal(fromLeaf) {
		t.Fatalf("fingerprint changed after reload: %s vs %s", fp, fromLeaf)
	}

	otherCert, _, err := GenerateServerIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherBlock, _ := pem.Decode(otherCert)
	otherLeaf, err := x509.ParseCertificate(otherBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if FingerprintOf(otherLeaf).Equal(fromLeaf) {
		t.Fatal("two generated identities share a fingerprint")
	}
}

func TestGenerateServerIdentityRejectsBadHostnames(t *testing.T) {
	for _, h := range []string{"bad host", "-leading.example", "a..b", "exa\x00mple", "ünicode.example"} {
		if _, _, err := GenerateServerIdentity([]string{h}); err == nil {
			t.Errorf("GenerateServerIdentity(%q) succeeded, want error", h)
		}
	}
}

func TestFingerprintOfTLSEmpty(t *testing.T) {
	if _, err := FingerprintOfTLS(tls.Certificate{}); err == nil {
		t.Fatal("FingerprintOfTLS on empty certificate succeeded")
	}
}

func TestLoadServerCertificateKeyTypes(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		signer crypto.Signer
		ok     bool
	}{
		{"ecdsa-p256", p256, true},
		{"ecdsa-p384", p384, true},
		{"ecdsa-p521", p521, false},
		{"rsa", rsaKey, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := selfSignedPEM(t, tc.signer)
			certPath, keyPath := writeIdentity(t, certPEM, keyPEM)
			_, err := LoadServerCertificate(certPath, keyPath)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadServerCertificateErrors(t *testing.T) {
	certA, keyA, err := GenerateServerIdentity([]string{"a.example"})
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := GenerateServerIdentity([]string{"b.example"})
	if err != nil {
		t.Fatal(err)
	}

	certPath, _ := writeIdentity(t, certA, keyA)
	_, wrongKeyPath := writeIdentity(t, certA, keyB)
	if _, err := LoadServerCertificate(certPath, wrongKeyPath); err == nil {
		t.Fatal("mismatched key accepted")
	}

	missing := filepath.Join(t.TempDir(), "missing.pem")
	if _, err := LoadServerCertificate(missing, missing); err == nil {
		t.Fatal("missing files accepted")
	}

	garbagePath, garbageKeyPath := writeIdentity(t, []byte("not pem"), []byte("not pem"))
	if _, err := LoadServerCertificate(garbagePath, garbageKeyPath); err == nil {
		t.Fatal("garbage PEM accepted")
	}
}
