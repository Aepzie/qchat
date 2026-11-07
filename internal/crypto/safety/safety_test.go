package safety

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// katNumber is the safety number for katParties. It pins the iteration, the
// rendering and the canonical ordering.
const katNumber = "959447110125817478073280067650789825262912167058074417145965"

func katParties() (idA [IDSize]byte, pubA []byte, idB [IDSize]byte, pubB []byte) {
	pubA = bytes.Repeat([]byte{0xaa}, 1984)
	pubB = bytes.Repeat([]byte{0xbb}, 1984)
	idA = sha256.Sum256(append([]byte("qchat-identity-v1"), pubA...))
	idB = sha256.Sum256(append([]byte("qchat-identity-v1"), pubB...))
	return idA, pubA, idB, pubB
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSignalVector checks the fingerprint core against the published test
// vector of Signal's NumericFingerprintGenerator (version 0, 5200
// iterations, phone numbers as stable identifiers). Signal orders the halves
// by comparing their digit strings; qchat orders by ID, so the test applies
// Signal's ordering itself.
func TestSignalVector(t *testing.T) {
	aliceKey := mustHex(t, "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
	bobKey := mustHex(t, "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
	alice := digits(iteratedFingerprint(aliceKey, []byte("+14152222222")))
	bob := digits(iteratedFingerprint(bobKey, []byte("+14153333333")))
	combined := alice + bob
	if bob < alice {
		combined = bob + alice
	}
	const want = "300354477692869396892869876765458257569162576843440918079131"
	if combined != want {
		t.Errorf("Signal vector = %s, want %s", combined, want)
	}
}

func TestKnownAnswer(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	got := Number(idA, pubA, idB, pubB)
	if got != katNumber {
		t.Errorf("Number = %s, want %s", got, katNumber)
	}
	if len(got) != Digits || !isNumber(got) {
		t.Errorf("Number %q is not %d digits", got, Digits)
	}
}

func TestNumberIsSymmetric(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	if Number(idA, pubA, idB, pubB) != Number(idB, pubB, idA, pubA) {
		t.Error("Number depends on argument order")
	}
	if QRPayload(idA, pubA, idB, pubB) != QRPayload(idB, pubB, idA, pubA) {
		t.Error("QRPayload depends on argument order")
	}
	if Number(idA, pubA, idA, pubB) != Number(idA, pubB, idA, pubA) {
		t.Error("Number with equal IDs depends on argument order")
	}
}

func TestSmallerIDFirst(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	halfA := digits(Fingerprint(idA, pubA))
	halfB := digits(Fingerprint(idB, pubB))
	want := halfA + halfB
	if bytes.Compare(idB[:], idA[:]) < 0 {
		want = halfB + halfA
	}
	if got := Number(idA, pubA, idB, pubB); got != want {
		t.Errorf("Number = %s, want smaller-ID half first: %s", got, want)
	}
}

func TestNumberChangesWithKeyOrID(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	base := Number(idA, pubA, idB, pubB)

	otherPub := bytes.Clone(pubA)
	otherPub[len(otherPub)-1] ^= 1
	if Number(idA, otherPub, idB, pubB) == base {
		t.Error("changing a public key does not change the number")
	}
	otherID := idB
	otherID[0] ^= 1
	if Number(idA, pubA, otherID, pubB) == base {
		t.Error("changing an ID does not change the number")
	}
}

func TestFingerprintDefinition(t *testing.T) {
	idA, pubA, _, _ := katParties()
	fp := Fingerprint(idA, pubA)
	if fp == [FingerprintSize]byte{} {
		t.Fatal("zero fingerprint")
	}
	if fp != iteratedFingerprint(pubA, idA[:]) {
		t.Error("Fingerprint does not use (publicKey, ID) order of the spec")
	}
}

func TestDigits(t *testing.T) {
	var fp [FingerprintSize]byte
	if got := digits(fp); got != strings.Repeat("0", 30) {
		t.Errorf("digits(zero) = %s", got)
	}
	for i := range fp {
		fp[i] = 0xff
	}
	// 2^40 - 1 = 1099511627775, mod 100000 = 27775.
	if got := digits(fp); got != strings.Repeat("27775", 6) {
		t.Errorf("digits(ff..) = %s", got)
	}
	fp = [FingerprintSize]byte{4: 0x07}
	if got := digits(fp)[:5]; got != "00007" {
		t.Errorf("first group = %s, want zero-padded 00007", got)
	}
}

func TestGrouped(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	number := Number(idA, pubA, idB, pubB)
	grouped := Grouped(number)
	groups := strings.Split(grouped, " ")
	if len(groups) != Groups {
		t.Fatalf("Grouped has %d groups, want %d: %q", len(groups), Groups, grouped)
	}
	for _, g := range groups {
		if len(g) != GroupSize {
			t.Errorf("group %q has %d digits", g, len(g))
		}
	}
	if strings.ReplaceAll(grouped, " ", "") != number {
		t.Error("Grouped changed the digits")
	}
	if Grouped(grouped) != grouped {
		t.Error("Grouped is not idempotent")
	}
	if got := Grouped("1234567"); got != "12345 67" {
		t.Errorf("Grouped(short) = %q", got)
	}
	if Grouped("") != "" {
		t.Error("Grouped(empty) not empty")
	}
}

func TestEqualNumbers(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	number := Number(idA, pubA, idB, pubB)
	grouped := Grouped(number)
	if !EqualNumbers(number, number) || !EqualNumbers(number, grouped) || !EqualNumbers(grouped, number) {
		t.Error("equal numbers compare unequal")
	}
	multiline := strings.Replace(grouped, " ", "\n", 5)
	if !EqualNumbers(number, " "+multiline+"\t\r\n") {
		t.Error("whitespace not ignored")
	}
	different := []byte(number)
	different[59] = '0' + (different[59]-'0'+1)%10
	for _, other := range []string{string(different), number[:59], number + "0", "", strings.Replace(number, number[:1], "a", 1), strings.Repeat("0", 61)} {
		if EqualNumbers(number, other) {
			t.Errorf("EqualNumbers(%q, %q) = true", number, other)
		}
	}
	if EqualNumbers("", "") || EqualNumbers("abc", "abc") {
		t.Error("non-numbers compare equal")
	}
}

func TestQRPayload(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	payload := QRPayload(idA, pubA, idB, pubB)
	first, second := idA, idB
	if bytes.Compare(idA[:], idB[:]) > 0 {
		first, second = idB, idA
	}
	want := "qchat-verify:1:" + hex.EncodeToString(first[:]) + ":" + hex.EncodeToString(second[:]) + ":" + katNumber
	if payload != want {
		t.Errorf("QRPayload = %s, want %s", payload, want)
	}

	gotFirst, gotSecond, number, err := ParseQRPayload(payload)
	if err != nil {
		t.Fatalf("ParseQRPayload: %v", err)
	}
	if gotFirst != first || gotSecond != second || number != katNumber {
		t.Error("ParseQRPayload returned different fields")
	}

	if !VerifyQRPayload(payload, idA, pubA, idB, pubB) || !VerifyQRPayload(payload, idB, pubB, idA, pubA) {
		t.Error("VerifyQRPayload rejects the correct payload")
	}
	otherPub := bytes.Clone(pubB)
	otherPub[0] ^= 1
	if VerifyQRPayload(payload, idA, pubA, idB, otherPub) {
		t.Error("VerifyQRPayload accepts a payload for a different key")
	}
}

func TestParseQRPayloadRejects(t *testing.T) {
	idA, pubA, idB, pubB := katParties()
	valid := QRPayload(idA, pubA, idB, pubB)
	first, second, number, err := ParseQRPayload(valid)
	if err != nil {
		t.Fatal(err)
	}
	h1, h2 := hex.EncodeToString(first[:]), hex.EncodeToString(second[:])
	cases := map[string]string{
		"empty":            "",
		"wrong prefix":     "qchat-verify:2:" + h1 + ":" + h2 + ":" + number,
		"uppercase hex":    QRPrefix + strings.ToUpper(h1) + ":" + h2 + ":" + number,
		"swapped IDs":      QRPrefix + h2 + ":" + h1 + ":" + number,
		"short ID":         QRPrefix + h1[2:] + ":" + h2 + ":" + number,
		"short number":     QRPrefix + h1 + ":" + h2 + ":" + number[1:],
		"grouped number":   QRPrefix + h1 + ":" + h2 + ":" + Grouped(number),
		"extra field":      valid + ":x",
		"trailing newline": valid + "\n",
		"non-hex":          QRPrefix + "zz" + h1[2:] + ":" + h2 + ":" + number,
	}
	for name, payload := range cases {
		if _, _, _, err := ParseQRPayload(payload); !errors.Is(err, ErrInvalidQRPayload) {
			t.Errorf("%s: err = %v, want ErrInvalidQRPayload", name, err)
		}
	}
}
