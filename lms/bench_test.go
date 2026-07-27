package lms

import (
	"fmt"
	"testing"
)

var benchOTS = []OTSType{LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8}

func BenchmarkKeyGenH10(b *testing.B) {
	seed, id := randomKey(b)
	for _, ots := range benchOTS {
		b.Run(ots.String(), func(b *testing.B) {
			for b.Loop() {
				if _, err := NewTree(LMS_SHA256_M32_H10, ots, seed, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignVerify(b *testing.B) {
	seed, id := randomKey(b)
	msg := make([]byte, 64)
	c := make([]byte, N)
	for _, ots := range benchOTS {
		tree, _ := NewTree(LMS_SHA256_M32_H10, ots, seed, id)
		sig, _ := tree.SignAt(0, c, msg)
		b.Run("sign/"+ots.String(), func(b *testing.B) {
			for b.Loop() {
				if _, err := tree.SignAt(5, c, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verify/"+ots.String(), func(b *testing.B) {
			for b.Loop() {
				if err := Verify(tree.PublicKey(), msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHSS(b *testing.B) {
	levels := []LevelParams{{LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4}, {LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4}}
	seed, id := randomKey(b)
	s, err := NewSigner(levels, seed, id, State{}, &MemoryStore{})
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	sig, _ := s.Sign(msg)
	b.Run(fmt.Sprintf("sign/%d-levels", len(levels)), func(b *testing.B) {
		// Most signatures reuse the cached bottom tree; one in 1024 rebuilds it.
		for b.Loop() {
			if _, err := s.Sign(msg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(fmt.Sprintf("verify/%d-levels", len(levels)), func(b *testing.B) {
		for b.Loop() {
			if err := VerifyHSS(s.PublicKey(), msg, sig); err != nil {
				b.Fatal(err)
			}
		}
	})
}
