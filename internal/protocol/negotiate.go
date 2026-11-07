package protocol

import "fmt"

// Negotiate picks the highest wire version that both the client, as described
// by h, and this implementation support. It fails with ErrMalformed if h does
// not describe a valid range and with ErrUnsupportedVersion if the ranges do
// not overlap. A server that cannot negotiate should reply with an
// [ErrorBody] carrying ErrCodeUnsupportedVersion and close the connection.
func Negotiate(h Hello) (uint8, error) {
	if err := h.validate(); err != nil {
		return 0, err
	}
	for i := len(supportedVersions) - 1; i >= 0; i-- {
		v := supportedVersions[i]
		if v >= h.MinVersion && v <= h.MaxVersion {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: client offers [%d, %d]", ErrUnsupportedVersion, h.MinVersion, h.MaxVersion)
}
