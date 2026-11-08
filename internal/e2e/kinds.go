package e2e

// Phase 7 message kinds (docs/design/phase-7-files.md). Each may travel
// both over a pairwise session and inside a group envelope; their bodies are
// binary and are parsed by the application layer.
const (
	// KindFileOffer announces a file: its metadata and the random key its
	// chunks are encrypted with.
	KindFileOffer Kind = 5
	// KindFileChunk carries one chunk of an offered file, already encrypted
	// with the file key.
	KindFileChunk Kind = 6
	// KindTimer sets the disappearing message timer of the conversation it
	// is sent in.
	KindTimer Kind = 7
)

// lastKind is the highest kind this package accepts: the sealed sender
// access key of Phase 5, numbered after the Phase 7 kinds.
const lastKind = KindAccessKey

// IsExtension reports whether k is one of the Phase 7 kinds, which are
// accepted both pairwise and inside group envelopes.
func (k Kind) IsExtension() bool { return k >= KindFileOffer && k <= KindTimer }
