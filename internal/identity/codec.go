package identity

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Limits applied by the strict decoder. Every structure handled by this
// package is a flat map with at most six entries, so these bounds are far
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
	// indefinite-length items and no tags. Signatures are computed over
	// these bytes, so the encoding of a given value must be unique.
	encMode cbor.EncMode

	// decMode is the strict decoder used for every structure.
	decMode cbor.DecMode

	// peekMode shares all limits with decMode but tolerates unknown fields.
	// It only reads the version of a structure that failed strict decoding,
	// so that data written by a newer format is reported as
	// ErrUnsupportedVersion rather than as malformed.
	peekMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden

	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("identity: invalid CBOR encoding options: " + err.Error())
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
		panic("identity: invalid CBOR decoding options: " + err.Error())
	}
	decOpts.ExtraReturnErrors = cbor.ExtraDecErrorNone
	if peekMode, err = decOpts.DecMode(); err != nil {
		panic("identity: invalid CBOR peek options: " + err.Error())
	}
}

// errNonCanonical is returned by decodeCanonical for input that decodes but
// is not the canonical encoding of the decoded value.
var errNonCanonical = errors.New("non-canonical encoding")

// versionPeek reads only field 1, the version of every structure defined by
// this package.
type versionPeek struct {
	Version uint64 `cbor:"1,keyasint"`
}

// peekVersion returns the version field of b, decoded leniently, and whether
// it could be read at all.
func peekVersion(b []byte) (uint64, bool) {
	var peek versionPeek
	if err := peekMode.Unmarshal(b, &peek); err != nil {
		return 0, false
	}
	return peek.Version, true
}

// decodeCanonical strictly decodes b into v and then requires b to be
// exactly the canonical encoding of v.
//
// Accepting a single encoding per value removes any room for parser
// differentials: two implementations (or the relay and a client) can never
// disagree about what a signed structure says, and a signature can never be
// carried over to an alternative encoding of the same fields (other integer
// widths, other key orders). Because no field is omitempty, the re-encoding
// also proves that every field was present: a missing field would reappear
// with its zero value and break the comparison.
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
