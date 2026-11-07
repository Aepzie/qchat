package e2e

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Limits applied by the strict decoder. Every structure handled by this
// package is a flat map with at most four entries, so these bounds are far
// above what valid input needs while keeping hostile input from making the
// decoder recurse or allocate without bound.
const (
	maxNestedLevels  = 4
	maxArrayElements = 16
	maxMapPairs      = 16
)

var (
	// encMode produces Core Deterministic CBOR (RFC 8949 section 4.2.1):
	// shortest integer and length encodings, sorted map keys, no
	// indefinite-length items and no tags. The decoder accepts only these
	// bytes, so the encoding of a given value must be unique.
	encMode cbor.EncMode

	// decMode is the strict decoder used for every structure.
	decMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden

	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("e2e: invalid CBOR encoding options: " + err.Error())
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
		panic("e2e: invalid CBOR decoding options: " + err.Error())
	}
}

// errNonCanonical is returned by decodeCanonical for input that decodes but
// is not the canonical encoding of the decoded value.
var errNonCanonical = errors.New("non-canonical encoding")

// decodeCanonical strictly decodes b into v and then requires b to be
// exactly the canonical encoding of v.
//
// Accepting a single encoding per value removes any room for parser
// differentials: two implementations can never disagree about what a
// structure says, and no structure has alternative encodings (other integer
// widths, other key orders). The re-encoding also proves that every required
// field was present: a missing field would reappear with its zero value (a
// nil byte string encodes as null) and break the comparison. For the one
// optional field, Envelope.Init, an explicitly encoded empty value is
// omitted on re-encoding and therefore rejected as well.
func decodeCanonical(b []byte, v any) error {
	if err := decMode.Unmarshal(b, v); err != nil {
		return err
	}
	canonical, err := encMode.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, b) {
		return errNonCanonical
	}
	return nil
}
