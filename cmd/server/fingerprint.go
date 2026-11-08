package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/transport"
)

// maxCertFileSize bounds how much of a certificate file is read.
const maxCertFileSize = 1 << 20

// cmdFingerprint prints the SPKI fingerprint of the server certificate,
// located either through a configuration file or in a data directory
// created by init.
//
// Only the certificate is read, never the private key, so the command also
// works for an account that may read the public certificate but not the key.
func cmdFingerprint(args []string, stdout, stderr io.Writer) error {
	fset := newFlagSet("fingerprint", "(--config FILE | --data-dir DIR)", stderr)
	configPath := fset.String("config", "", "path of server.toml")
	dataDir := fset.String("data-dir", "", "data directory created by init")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	if (*configPath == "") == (*dataDir == "") {
		return usagef(fset, "exactly one of --config and --data-dir is required")
	}

	certPath := filepath.Join(*dataDir, certFileName)
	if *configPath != "" {
		cfg, err := server.LoadConfig(*configPath)
		if err != nil {
			return err
		}
		certPath = cfg.TLSCert
	}

	pin, err := certificateFingerprint(certPath)
	if err != nil {
		return err
	}
	printFingerprint(stdout, pin)
	return nil
}

// certificateFingerprint returns the fingerprint of the first certificate
// in the PEM file at path.
func certificateFingerprint(path string) (transport.Fingerprint, error) {
	cert, err := readCertificate(path)
	if err != nil {
		return transport.Fingerprint{}, err
	}
	return transport.FingerprintOf(cert), nil
}

// readCertificate parses the first certificate in the PEM file at path.
func readCertificate(path string) (*x509.Certificate, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, maxCertFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	if len(content) > maxCertFileSize {
		return nil, fmt.Errorf("read certificate: %s is larger than %d bytes", path, maxCertFileSize)
	}
	for rest := content; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("read certificate: no CERTIFICATE block found in " + path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
}
