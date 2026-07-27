package lms

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type rfcCase struct {
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	Message      string `json:"message"`
	Signature    string `json:"signature"`
	PrivateSeeds []struct {
		Seed string `json:"seed"`
		I    string `json:"i"`
	} `json:"private_seeds"`
}

func rfcCases(t *testing.T) []rfcCase {
	t.Helper()
	raw, err := os.ReadFile("../testdata/rfc8554.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []rfcCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) != 2 {
		t.Fatalf("want 2 RFC 8554 test cases, got %d", len(file.Cases))
	}
	return file.Cases
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC8554Verify(t *testing.T) {
	for _, c := range rfcCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			pub, err := ParseHSSPublicKey(mustHex(t, c.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			msg := mustHex(t, c.Message)
			sig := mustHex(t, c.Signature)
			if err := VerifyHSS(pub, msg, sig); err != nil {
				t.Fatalf("official signature rejected: %v", err)
			}
			bad := append([]byte{}, msg...)
			bad[0] ^= 1
			if err := VerifyHSS(pub, bad, sig); !errors.Is(err, ErrInvalid) {
				t.Fatalf("modified message: got %v", err)
			}
		})
	}
}

// Test Case 2 publishes the SEED and I of both levels (Appendix A key
// generation), so both public keys can be recomputed exactly.
func TestRFC8554KeyGeneration(t *testing.T) {
	c := rfcCases(t)[1]
	if len(c.PrivateSeeds) != 2 {
		t.Fatal("test case 2 should list two private seeds")
	}
	pub, err := ParseHSSPublicKey(mustHex(t, c.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sig := mustHex(t, c.Signature)
	top := pub.Top
	topSigLen := top.Type.SignatureSize(top.OTSType)
	embedded, err := ParsePublicKey(sig[4+topSigLen : 4+topSigLen+PublicKeySize])
	if err != nil {
		t.Fatal(err)
	}
	for level, want := range []PublicKey{top, embedded} {
		var seed [N]byte
		var id [IdentifierSize]byte
		copy(seed[:], mustHex(t, c.PrivateSeeds[level].Seed))
		copy(id[:], mustHex(t, c.PrivateSeeds[level].I))
		tree, err := NewTree(want.Type, want.OTSType, seed, id)
		if err != nil {
			t.Fatal(err)
		}
		if got := tree.PublicKey(); !equalKeys(got, want) {
			t.Fatalf("level %d: derived %x, want %x", level, got.Bytes(), want.Bytes())
		}
		// Re-sign with the published leaf index and randomizer C; the result
		// must equal that level's part of the HSS signature exactly.
		var part, signed []byte
		if level == 0 {
			part = sig[4 : 4+topSigLen]
			signed = embedded.Bytes()
		} else {
			part = sig[4+topSigLen+PublicKeySize:]
			signed = mustHex(t, c.Message)
		}
		q := binary.BigEndian.Uint32(part)
		got, err := tree.SignAt(q, part[8:8+N], signed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, part) {
			t.Fatalf("level %d: regenerated signature differs", level)
		}
	}
}
