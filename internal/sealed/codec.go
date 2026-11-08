package sealed

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Limits of the strict decoder, the smallest the CBOR library allows. Both
// structures are flat maps of two fields, so these bounds are far above
// what valid input needs.
const (
	maxNestedLevels  = 4
	maxArrayElements = 16
	maxMapPairs      = 16
)

var (
	// encMode produces Core Deterministic CBOR without indefinite lengths
	// or tags.
	encMode cbor.EncMode
	// decMode is the strict decoder for both structures.
	decMode cbor.DecMode
	// peekMode tolerates unknown fields; it reads only the version of an
	// envelope that failed strict decoding.
	peekMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden
	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("sealed: invalid CBOR encoding options: " + err.Error())
	}
	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		BignumTag:         cbor.BignumTagForbidden,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   maxNestedLevels,
		MaxArrayElements:  maxArrayElements,
		MaxMapPairs:       maxMapPairs,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	if decMode, err = decOpts.DecMode(); err != nil {
		panic("sealed: invalid CBOR decoding options: " + err.Error())
	}
	decOpts.ExtraReturnErrors = cbor.ExtraDecErrorNone
	if peekMode, err = decOpts.DecMode(); err != nil {
		panic("sealed: invalid CBOR peek options: " + err.Error())
	}
}

// errNonCanonical reports input that decodes but is not the canonical
// encoding of the decoded value, including input with missing fields.
var errNonCanonical = errors.New("non-canonical encoding")

// decodeCanonical strictly decodes b into v and requires b to be exactly
// the canonical encoding of the result.
func decodeCanonical(b []byte, v any) error {
	if err := decMode.Unmarshal(b, v); err != nil {
		return err
	}
	canon, err := encMode.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(canon, b) {
		return errNonCanonical
	}
	return nil
}

// versionPeek reads only the version key of an envelope.
type versionPeek struct {
	Version *uint64 `cbor:"1,keyasint"`
}

// peekVersion returns the version of an envelope that did not decode
// strictly, if it has one.
func peekVersion(b []byte) (uint64, bool) {
	var peek versionPeek
	if err := peekMode.Unmarshal(b, &peek); err != nil || peek.Version == nil {
		return 0, false
	}
	return *peek.Version, true
}
