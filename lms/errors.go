package lms

import "errors"

var (
	ErrUnsupportedType = errors.New("lms: unsupported parameter set")
	ErrMalformed       = errors.New("lms: malformed encoding")
	ErrInvalid         = errors.New("lms: signature does not verify")
	ErrExhausted       = errors.New("lms: all one-time keys have been used")
	ErrStateReuse      = errors.New("lms: refusing to reuse a one-time key")
)
