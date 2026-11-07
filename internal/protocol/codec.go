package protocol

import (
	"github.com/fxamacker/cbor/v2"
)

// Limits applied by the strict decoder. They are far above what any frame or
// body defined by this package needs, yet small enough that hostile input
// cannot make the decoder allocate or recurse without bound.
const (
	maxNestedLevels  = 8
	maxArrayElements = 16
	maxMapPairs      = 16
)

var (
	// encMode produces Core Deterministic CBOR: shortest integer and length
	// encodings, sorted map keys, no indefinite-length items and no tags.
	encMode cbor.EncMode

	// decMode is the strict decoder used for every frame and body.
	decMode cbor.DecMode

	// peekMode shares all limits with decMode but tolerates unknown fields.
	// It is used only to read the version of a frame before strict decoding,
	// so that frames from a newer protocol version are reported as
	// ErrUnsupportedVersion rather than ErrMalformed.
	peekMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.IndefLength = cbor.IndefLengthForbidden
	encOpts.TagsMd = cbor.TagsForbidden

	var err error
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic("protocol: invalid CBOR encoding options: " + err.Error())
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
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic("protocol: invalid CBOR decoding options: " + err.Error())
	}

	decOpts.ExtraReturnErrors = cbor.ExtraDecErrorNone
	peekMode, err = decOpts.DecMode()
	if err != nil {
		panic("protocol: invalid CBOR peek options: " + err.Error())
	}
}
