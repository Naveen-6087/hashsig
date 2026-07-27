package lms

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MaxLevels is the largest HSS depth allowed by RFC 8554 section 6.
const MaxLevels = 8

// HSSPublicKey is u32str(L) || the top-level LMS public key.
type HSSPublicKey struct {
	Levels uint32
	Top    PublicKey
}

func (pk HSSPublicKey) Bytes() []byte {
	return append(u32(pk.Levels), pk.Top.Bytes()...)
}

func ParseHSSPublicKey(b []byte) (HSSPublicKey, error) {
	var pk HSSPublicKey
	if len(b) != 4+PublicKeySize {
		return pk, fmt.Errorf("%w: HSS public key is %d bytes, want %d", ErrMalformed, len(b), 4+PublicKeySize)
	}
	pk.Levels = binary.BigEndian.Uint32(b)
	if pk.Levels < 1 || pk.Levels > MaxLevels {
		return pk, fmt.Errorf("%w: %d HSS levels", ErrMalformed, pk.Levels)
	}
	top, err := ParsePublicKey(b[4:])
	if err != nil {
		return pk, err
	}
	pk.Top = top
	return pk, nil
}

// VerifyHSS checks an HSS signature (RFC 8554 section 6.3): Nspk signed
// public keys, each certifying the next level, then a signature on msg by the
// bottom-level key.
func VerifyHSS(pub HSSPublicKey, msg, sig []byte) error {
	if len(sig) < 4 {
		return fmt.Errorf("%w: HSS signature too short", ErrMalformed)
	}
	nspk := binary.BigEndian.Uint32(sig)
	if nspk+1 != pub.Levels {
		return fmt.Errorf("%w: signature has %d signed keys for a %d-level key", ErrMalformed, nspk, pub.Levels)
	}
	rest := sig[4:]
	key := pub.Top
	for i := uint32(0); i < nspk; i++ {
		lmsSig, err := splitLMSSignature(key, rest)
		if err != nil {
			return fmt.Errorf("level %d: %w", i, err)
		}
		rest = rest[len(lmsSig):]
		if len(rest) < PublicKeySize {
			return fmt.Errorf("%w: missing public key for level %d", ErrMalformed, i+1)
		}
		next, err := ParsePublicKey(rest[:PublicKeySize])
		if err != nil {
			return fmt.Errorf("level %d: %w", i+1, err)
		}
		if err := Verify(key, rest[:PublicKeySize], lmsSig); err != nil {
			return fmt.Errorf("level %d: %w", i, err)
		}
		rest = rest[PublicKeySize:]
		key = next
	}
	lmsSig, err := splitLMSSignature(key, rest)
	if err != nil {
		return fmt.Errorf("level %d: %w", nspk, err)
	}
	if len(lmsSig) != len(rest) {
		return fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(rest)-len(lmsSig))
	}
	if err := Verify(key, msg, lmsSig); err != nil {
		return fmt.Errorf("level %d: %w", nspk, err)
	}
	return nil
}

// splitLMSSignature returns the LMS signature at the start of b. Its length
// follows from the LM-OTS type inside it and the LMS type after it, both of
// which must match key.
func splitLMSSignature(key PublicKey, b []byte) ([]byte, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("%w: LMS signature too short", ErrMalformed)
	}
	if OTSType(binary.BigEndian.Uint32(b[4:])) != key.OTSType {
		return nil, fmt.Errorf("%w: LM-OTS type does not match the public key", ErrMalformed)
	}
	n := key.Type.SignatureSize(key.OTSType)
	if n == 0 || len(b) < n {
		return nil, fmt.Errorf("%w: LMS signature truncated", ErrMalformed)
	}
	return b[:n], nil
}

// HSSSignatureSize is the size of an HSS signature for the given levels.
func HSSSignatureSize(levels []LevelParams) int {
	size := 4
	for i, l := range levels {
		size += l.Type.SignatureSize(l.OTSType)
		if i+1 < len(levels) {
			size += PublicKeySize
		}
	}
	return size
}

// LevelParams are the LMS and LM-OTS types of one HSS level.
type LevelParams struct {
	Type    Type
	OTSType OTSType
}

func (l LevelParams) String() string { return l.Type.String() + "/" + l.OTSType.String() }

func equalKeys(a, b PublicKey) bool { return bytes.Equal(a.Bytes(), b.Bytes()) }
