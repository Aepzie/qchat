package sealbox

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncapsulateRoundTrip(t *testing.T) {
	key := newKey(t)
	enc, secret, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(enc) != EncapsulatedKeySize || EncapsulatedKeySize != 1120 {
		t.Fatalf("enc length = %d, want 1120", len(enc))
	}
	if secret == ([SharedSecretSize]byte{}) {
		t.Fatal("secret is all zero")
	}
	got, err := Decapsulate(key, enc, testInfo)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if got != secret {
		t.Fatal("decapsulated secret differs")
	}
}

func TestEncapsulateFresh(t *testing.T) {
	key := newKey(t)
	enc1, s1, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	enc2, s2, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) || s1 == s2 {
		t.Fatal("two encapsulations are identical")
	}
}

func TestDecapsulateMismatch(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	enc, secret, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decapsulate(key, enc, []byte("qchat/test/other")); err == nil && got == secret {
		t.Error("wrong info yields the same secret")
	}
	if got, err := Decapsulate(other, enc, testInfo); err == nil && got == secret {
		t.Error("wrong key yields the same secret")
	}
	tampered := bytes.Clone(enc)
	tampered[0] ^= 1
	if got, err := Decapsulate(key, tampered, testInfo); err == nil && got == secret {
		t.Error("tampered enc yields the same secret")
	}
	tampered = bytes.Clone(enc)
	tampered[len(tampered)-1] ^= 1
	if got, err := Decapsulate(key, tampered, testInfo); err == nil && got == secret {
		t.Error("tampered X25519 part yields the same secret")
	}
}

func TestEncapsulateDiffersFromSeal(t *testing.T) {
	key := newKey(t)
	enc, secret, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, testInfo, append(enc, secret[:16]...)); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Open on an export-only encapsulation = %v, want ErrDecrypt", err)
	}
}

func TestEncapsulateRejectsBadInput(t *testing.T) {
	key := newKey(t)
	if _, _, err := Encapsulate(key.Public(), nil); !errors.Is(err, ErrInvalidInfo) {
		t.Errorf("Encapsulate(nil info) = %v, want ErrInvalidInfo", err)
	}
	if _, _, err := Encapsulate(key.Public(), []byte{}); !errors.Is(err, ErrInvalidInfo) {
		t.Errorf("Encapsulate(empty info) = %v, want ErrInvalidInfo", err)
	}
	if _, _, err := Encapsulate(nil, testInfo); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("Encapsulate(nil key) = %v, want ErrInvalidPublicKey", err)
	}
	enc, _, err := Encapsulate(key.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decapsulate(key, enc, nil); !errors.Is(err, ErrInvalidInfo) {
		t.Errorf("Decapsulate(empty info) = %v, want ErrInvalidInfo", err)
	}
	if _, err := Decapsulate(nil, enc, testInfo); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Decapsulate(nil key) = %v, want ErrInvalidPrivateKey", err)
	}
	for _, n := range []int{0, 1, EncapsulatedKeySize - 1, EncapsulatedKeySize + 1} {
		if _, err := Decapsulate(key, make([]byte, n), testInfo); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Decapsulate(%d-byte enc) = %v, want ErrDecrypt", n, err)
		}
	}
	destroyed := newKey(t)
	enc, _, err = Encapsulate(destroyed.Public(), testInfo)
	if err != nil {
		t.Fatal(err)
	}
	destroyed.Destroy()
	if _, err := Decapsulate(destroyed, enc, testInfo); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Decapsulate after Destroy = %v, want ErrInvalidPrivateKey", err)
	}
}
