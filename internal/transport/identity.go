package transport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// maxPEMFileSize bounds how much is read from a certificate or key file, so a
// misconfigured path (for example a device or a huge log file) cannot exhaust
// memory.
const maxPEMFileSize = 1 << 20

// serverCommonName is a fixed, uninformative subject name. Clients ignore the
// subject entirely because trust comes from the SPKI pin.
const serverCommonName = "qchat server"

// GenerateServerIdentity creates a new self-signed server certificate with a
// fresh Ed25519 key pair and returns both as PEM:
//
//   - certPEM holds one "CERTIFICATE" block;
//   - keyPEM holds the private key as a PKCS#8 "PRIVATE KEY" block. It is
//     secret and must be stored with restrictive permissions.
//
// hostnames become Subject Alternative Names. Entries that parse as IP
// addresses go into the IP SAN list, everything else into the DNS SAN list.
// Duplicates and empty entries are dropped. SANs are informational only:
// qchat clients authenticate the server by its key fingerprint, never by
// hostname.
//
// The certificate validity extends to the end of year 9999 (the RFC 5280
// "no well-defined expiration" value). Expiry would add no security here:
// clients do not check validity dates, because the pin is the trust anchor
// and rotating the key means distributing a new fingerprint anyway.
func GenerateServerIdentity(hostnames []string) (certPEM, keyPEM []byte, err error) {
	dnsNames, ips, err := splitSANs(hostnames)
	if err != nil {
		return nil, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: generate Ed25519 key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverCommonName},
		NotBefore:             notBefore,
		NotAfter:              time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: create certificate: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: encode private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	return certPEM, keyPEM, nil
}

// LoadServerCertificate reads a PEM certificate and its PEM private key from
// disk and returns them ready for ServerTLSConfig.
//
// Accepted key types are Ed25519 (what GenerateServerIdentity produces) and
// ECDSA on P-256 or P-384, which some operators may already have. RSA and
// other key types are rejected to keep the set of supported algorithms small.
// The certificate's public key must match the private key.
//
// Errors never include file contents, so key material cannot leak into logs.
func LoadServerCertificate(certPEMPath, keyPEMPath string) (tls.Certificate, error) {
	certPEM, err := readBoundedFile(certPEMPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: read certificate file: %w", err)
	}
	keyPEM, err := readBoundedFile(keyPEMPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: read private key file: %w", err)
	}
	defer clear(keyPEM)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: load key pair: %w", err)
	}

	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("transport: parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}

	if err := checkServerKeyType(cert.PrivateKey); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// checkServerKeyType enforces the allow-list of server key algorithms.
func checkServerKeyType(key any) error {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return nil
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return errors.New("transport: unsupported ECDSA curve (want P-256 or P-384)")
	default:
		return fmt.Errorf("transport: unsupported private key type %T (want Ed25519 or ECDSA P-256/P-384)", key)
	}
}

// randomSerial returns a uniformly random, non-zero 128-bit serial number.
// Serial numbers have no security role for a pinned self-signed certificate,
// but random serials avoid accidental collisions between re-issued
// certificates.
func randomSerial() (*big.Int, error) {
	var b [16]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("transport: generate serial number: %w", err)
		}
		serial := new(big.Int).SetBytes(b[:])
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// splitSANs normalises and de-duplicates hostnames into DNS names and IPs.
func splitSANs(hostnames []string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ips []net.IP
	seen := make(map[string]bool)

	for _, raw := range hostnames {
		h := strings.TrimSpace(raw)
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
			h = h[1 : len(h)-1]
		}
		if h == "" {
			continue
		}

		if ip := net.ParseIP(h); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			key := "ip:" + ip.String()
			if !seen[key] {
				seen[key] = true
				ips = append(ips, ip)
			}
			continue
		}

		name := strings.TrimSuffix(strings.ToLower(h), ".")
		if err := validateDNSName(name); err != nil {
			return nil, nil, err
		}
		key := "dns:" + name
		if !seen[key] {
			seen[key] = true
			dnsNames = append(dnsNames, name)
		}
	}
	return dnsNames, ips, nil
}

// validateDNSName performs a conservative syntax check on a lowercase DNS
// name: 1 to 253 characters, dot-separated labels of 1 to 63 characters made
// of letters, digits, '-' and '_', with no label starting or ending in '-'.
func validateDNSName(name string) error {
	if len(name) == 0 || len(name) > 253 {
		return errors.New("transport: invalid hostname length")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("transport: invalid hostname %q: bad label length", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("transport: invalid hostname %q: label starts or ends with '-'", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return fmt.Errorf("transport: invalid hostname %q: unexpected character", name)
			}
		}
	}
	return nil
}

// readBoundedFile reads at most maxPEMFileSize bytes and fails if the file is
// larger.
func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from the local operator's configuration; reads are size-bounded
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(io.LimitReader(f, maxPEMFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxPEMFileSize {
		clear(content)
		return nil, fmt.Errorf("file larger than %d bytes", maxPEMFileSize)
	}
	return content, nil
}
