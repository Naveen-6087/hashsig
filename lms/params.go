package lms

import "fmt"

// Domain separators from RFC 8554 section 7.1.
const (
	dPBLC = 0x8080
	dMESG = 0x8181
	dLEAF = 0x8282
	dINTR = 0x8383
)

const (
	// N is the hash output length: all parameter sets here use SHA-256 with
	// n = m = 32 (RFC 8554 sections 4.1 and 5.1).
	N = 32
	// IdentifierSize is the length of the tree identifier I.
	IdentifierSize = 16
)

// OTSType is an LM-OTS typecode (RFC 8554 section 4.1).
type OTSType uint32

const (
	LMOTS_SHA256_N32_W1 OTSType = 1
	LMOTS_SHA256_N32_W2 OTSType = 2
	LMOTS_SHA256_N32_W4 OTSType = 3
	LMOTS_SHA256_N32_W8 OTSType = 4
)

type otsParams struct {
	w  uint // Winternitz parameter: bits per chain digit
	p  int  // number of n-byte chains
	ls uint // left shift for the checksum
}

var otsTable = map[OTSType]otsParams{
	LMOTS_SHA256_N32_W1: {w: 1, p: 265, ls: 7},
	LMOTS_SHA256_N32_W2: {w: 2, p: 133, ls: 6},
	LMOTS_SHA256_N32_W4: {w: 4, p: 67, ls: 4},
	LMOTS_SHA256_N32_W8: {w: 8, p: 34, ls: 0},
}

func (t OTSType) params() (otsParams, error) {
	p, ok := otsTable[t]
	if !ok {
		return otsParams{}, fmt.Errorf("%w: LM-OTS type %d", ErrUnsupportedType, uint32(t))
	}
	return p, nil
}

// SignatureSize is the LM-OTS signature length: type, C and p chain values.
func (t OTSType) SignatureSize() int {
	p, err := t.params()
	if err != nil {
		return 0
	}
	return 4 + N + p.p*N
}

func (t OTSType) String() string {
	switch t {
	case LMOTS_SHA256_N32_W1:
		return "LMOTS_SHA256_N32_W1"
	case LMOTS_SHA256_N32_W2:
		return "LMOTS_SHA256_N32_W2"
	case LMOTS_SHA256_N32_W4:
		return "LMOTS_SHA256_N32_W4"
	case LMOTS_SHA256_N32_W8:
		return "LMOTS_SHA256_N32_W8"
	}
	return fmt.Sprintf("LMOTS(%d)", uint32(t))
}

// Type is an LMS typecode (RFC 8554 section 5.1).
type Type uint32

const (
	LMS_SHA256_M32_H5  Type = 5
	LMS_SHA256_M32_H10 Type = 6
	LMS_SHA256_M32_H15 Type = 7
	LMS_SHA256_M32_H20 Type = 8
	LMS_SHA256_M32_H25 Type = 9
)

var heights = map[Type]uint{
	LMS_SHA256_M32_H5:  5,
	LMS_SHA256_M32_H10: 10,
	LMS_SHA256_M32_H15: 15,
	LMS_SHA256_M32_H20: 20,
	LMS_SHA256_M32_H25: 25,
}

// Height is the tree height h; a key signs at most 2^h messages.
func (t Type) Height() (uint, error) {
	h, ok := heights[t]
	if !ok {
		return 0, fmt.Errorf("%w: LMS type %d", ErrUnsupportedType, uint32(t))
	}
	return h, nil
}

// SignatureSize is the LMS signature length for a given LM-OTS type.
func (t Type) SignatureSize(ots OTSType) int {
	h, err := t.Height()
	if err != nil || ots.SignatureSize() == 0 {
		return 0
	}
	return 4 + ots.SignatureSize() + 4 + int(h)*N
}

// PublicKeySize is the LMS public key length.
const PublicKeySize = 4 + 4 + IdentifierSize + N

func (t Type) String() string {
	if h, err := t.Height(); err == nil {
		return fmt.Sprintf("LMS_SHA256_M32_H%d", h)
	}
	return fmt.Sprintf("LMS(%d)", uint32(t))
}

// ParseOTSType and ParseType accept the RFC names, e.g. "LMOTS_SHA256_N32_W4".
func ParseOTSType(s string) (OTSType, error) {
	for t := range otsTable {
		if t.String() == s {
			return t, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnsupportedType, s)
}

func ParseType(s string) (Type, error) {
	for t := range heights {
		if t.String() == s {
			return t, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnsupportedType, s)
}
