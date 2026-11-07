package group

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Limits applied by the strict decoder. Controls and states are flat maps of
// at most ten entries whose only arrays are member lists. maxArrayElements
// is above [MaxMembers] so that an oversized list is reported by validation
// as [ErrTooManyMembers]; the element count is in any case bounded by the
// input size limits, so it cannot amplify allocation.
const (
	maxNestedLevels  = 4
	maxArrayElements = 4 * MaxMembers
	maxMapPairs      = 16
)

var (
	// encMode produces core deterministic CBOR: shortest integer and length
	// encodings, sorted map keys, no indefinite-length items and no tags.
	// Nil slices are encoded as empty arrays, so that a missing list and an
	// empty one cannot be two encodings of the same value.
	encMode cbor.EncMode

	// decMode is the strict decoder used for every structure.
	decMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden
	encOpts.NilContainers = cbor.NilContainerAsEmpty

	var err error
	if encMode, err = encOpts.EncMode(); err != nil {
		panic("group: invalid CBOR encoding options: " + err.Error())
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
		panic("group: invalid CBOR decoding options: " + err.Error())
	}
}

// errNonCanonical is returned by decodeCanonical for input that decodes but
// is not the canonical encoding of the decoded value.
var errNonCanonical = errors.New("non-canonical encoding")

// decodeCanonical strictly decodes b into v and then requires b to be
// exactly the canonical encoding of v.
//
// Accepting a single encoding per value means two clients can never
// disagree about what a signed control says or what a state hashes to, and
// a signature can never be carried over to an alternative encoding of the
// same fields. Because no field is omitempty, the re-encoding also proves
// that every field was present, and byte strings of the wrong length for a
// fixed-size field cannot survive the round trip.
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
