package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/craguS/qchat/internal/transport"
)

const pinA = "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const pinB = "sha256:ff02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func mustPin(t *testing.T, s string) transport.Fingerprint {
	t.Helper()
	fp, err := transport.ParseFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func flags(t *testing.T, args ...string) options {
	t.Helper()
	o, err := parseFlags(args, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestResolveWithoutEmbedding(t *testing.T) {
	got, err := resolveTarget(embedded{}, flags(t, "--server", "chat.example.org:443", "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	if got.addr != "chat.example.org:443" || !got.pin.Equal(mustPin(t, pinA)) || got.locked {
		t.Fatalf("target = %+v", got)
	}

	cases := map[string][]string{
		"missing --server and --pin":                  nil,
		"missing --server":                            {"--pin", pinA},
		"missing --pin":                               {"--server", "chat.example.org:443"},
		"--server: transport: invalid server address": {"--server", "chat.example.org", "--pin", pinA},
		"illegal character in host":                   {"--server", "user@chat.example.org:443", "--pin", pinA},
		"--pin:":                                      {"--server", "chat.example.org:443", "--pin", "sha256:abcd"},
	}
	for want, args := range cases {
		_, err := resolveTarget(embedded{}, flags(t, args...))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("args %v: error %v, want it to contain %q", args, err, want)
		}
	}
}

func TestResolveLockedBuild(t *testing.T) {
	emb := embedded{addr: "locked.example.org:443", pin: mustPin(t, pinA), ok: true}

	for _, args := range [][]string{
		nil,
		{"--server", "locked.example.org:443"},
		{"--server", "locked.example.org:0443"},
		{"--pin", strings.ToUpper(pinA[7:])},
		{"--server", "locked.example.org:443", "--pin", pinA},
	} {
		got, err := resolveTarget(emb, flags(t, args...))
		if err != nil {
			t.Errorf("args %v: %v", args, err)
			continue
		}
		if got.addr != emb.addr || !got.pin.Equal(emb.pin) || !got.locked {
			t.Errorf("args %v: target %+v", args, got)
		}
	}

	for _, args := range [][]string{
		{"--server", "evil.example.org:443"},
		{"--server", "user@locked.example.org:443"},
		{"--pin", pinB},
		{"--pin", "garbage"},
		{"--server", "locked.example.org:443", "--pin", pinB},
	} {
		_, err := resolveTarget(emb, flags(t, args...))
		if err == nil || err.Error() != "this client is locked to locked.example.org:443" {
			t.Errorf("args %v: error %v, want lock error", args, err)
		}
	}
}

func TestResolveBrokenEmbedding(t *testing.T) {
	_, err := resolveTarget(embedded{err: errors.New("bad pin")}, flags(t, "--server", "a:1", "--pin", pinA))
	if err == nil || !strings.Contains(err.Error(), "misconfigured") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunVersionAndUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "qchat ") {
		t.Fatalf("--version: code %d, out %q", code, out.String())
	}
	out.Reset()
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "missing --server and --pin") {
		t.Fatalf("no flags: code %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"stray"}, &out, &errOut); code != 2 {
		t.Fatalf("stray argument: code %d", code)
	}
	if code := run([]string{"--bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown flag: code %d", code)
	}
}
