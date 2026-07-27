package lms

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
)

func randomKey(t testing.TB) ([N]byte, [IdentifierSize]byte) {
	t.Helper()
	var seed [N]byte
	var id [IdentifierSize]byte
	rand.Read(seed[:])
	rand.Read(id[:])
	return seed, id
}

func TestLMSAllOTSTypes(t *testing.T) {
	for _, ots := range []OTSType{LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8} {
		t.Run(ots.String(), func(t *testing.T) {
			seed, id := randomKey(t)
			tree, err := NewTree(LMS_SHA256_M32_H5, ots, seed, id)
			if err != nil {
				t.Fatal(err)
			}
			pub := tree.PublicKey()
			if len(pub.Bytes()) != PublicKeySize {
				t.Fatal("public key size")
			}
			c := bytes.Repeat([]byte{7}, N)
			for _, q := range []uint32{0, 1, 17, 31} {
				msg := []byte{byte(q), 'm'}
				sig, err := tree.SignAt(q, c, msg)
				if err != nil {
					t.Fatal(err)
				}
				if len(sig) != LMS_SHA256_M32_H5.SignatureSize(ots) {
					t.Fatalf("signature size %d", len(sig))
				}
				if err := Verify(pub, msg, sig); err != nil {
					t.Fatalf("q=%d: %v", q, err)
				}
				if err := Verify(pub, []byte("other"), sig); !errors.Is(err, ErrInvalid) {
					t.Fatalf("wrong message accepted: %v", err)
				}
			}
			if _, err := tree.SignAt(32, c, nil); !errors.Is(err, ErrExhausted) {
				t.Fatalf("index 32 of an H5 tree: %v", err)
			}
		})
	}
}

func TestVerifyRejectsMalformedSignatures(t *testing.T) {
	seed, id := randomKey(t)
	tree, _ := NewTree(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W4, seed, id)
	pub := tree.PublicKey()
	msg := []byte("hello")
	sig, _ := tree.SignAt(3, make([]byte, N), msg)

	if err := Verify(pub, msg, sig[:len(sig)-1]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated: %v", err)
	}
	if err := Verify(pub, msg, append(sig, 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("extended: %v", err)
	}
	q99 := append([]byte{}, sig...)
	binary.BigEndian.PutUint32(q99, 99)
	if err := Verify(pub, msg, q99); !errors.Is(err, ErrMalformed) {
		t.Errorf("leaf index out of range: %v", err)
	}
	otsType := append([]byte{}, sig...)
	binary.BigEndian.PutUint32(otsType[4:], uint32(LMOTS_SHA256_N32_W8))
	if err := Verify(pub, msg, otsType); !errors.Is(err, ErrMalformed) {
		t.Errorf("mismatched LM-OTS type: %v", err)
	}
	// Flipping any single byte after the type fields must invalidate it.
	for _, i := range []int{3, 9, 4 + 4 + N + 5, len(sig) - 1} {
		bad := append([]byte{}, sig...)
		bad[i] ^= 0x10
		if err := Verify(pub, msg, bad); err == nil {
			t.Errorf("byte %d flipped but signature verified", i)
		}
	}
}

func TestParsePublicKeys(t *testing.T) {
	seed, id := randomKey(t)
	tree, _ := NewTree(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, seed, id)
	pk, err := ParsePublicKey(tree.PublicKey().Bytes())
	if err != nil || !equalKeys(pk, tree.PublicKey()) {
		t.Fatalf("round trip: %v", err)
	}
	b := tree.PublicKey().Bytes()
	binary.BigEndian.PutUint32(b, 42)
	if _, err := ParsePublicKey(b); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("unknown LMS type: %v", err)
	}
	if _, err := ParsePublicKey(b[:10]); !errors.Is(err, ErrMalformed) {
		t.Errorf("short key: %v", err)
	}
	hss := HSSPublicKey{Levels: 9, Top: tree.PublicKey()}
	if _, err := ParseHSSPublicKey(hss.Bytes()); !errors.Is(err, ErrMalformed) {
		t.Errorf("9 levels: %v", err)
	}
	if typ, err := ParseType("LMS_SHA256_M32_H10"); err != nil || typ != LMS_SHA256_M32_H10 {
		t.Errorf("ParseType: %v %v", typ, err)
	}
	if _, err := ParseOTSType("LMOTS_SHA256_N32_W3"); err == nil {
		t.Error("W3 does not exist")
	}
}

func h5w4(levels int) []LevelParams {
	out := make([]LevelParams, levels)
	for i := range out {
		out[i] = LevelParams{Type: LMS_SHA256_M32_H5, OTSType: LMOTS_SHA256_N32_W4}
	}
	return out
}

func TestHSSRoundTripAndExhaustion(t *testing.T) {
	for _, levels := range []int{1, 2} {
		seed, id := randomKey(t)
		store := &MemoryStore{}
		s, err := NewSigner(h5w4(levels), seed, id, State{}, store)
		if err != nil {
			t.Fatal(err)
		}
		pub := s.PublicKey()
		total := uint64(1) << (5 * levels)
		if s.Remaining() != total {
			t.Fatalf("remaining %d, want %d", s.Remaining(), total)
		}
		seen := map[string]bool{}
		for i := uint64(0); i < total; i++ {
			msg := binary.BigEndian.AppendUint64(nil, i)
			sig, err := s.Sign(msg)
			if err != nil {
				t.Fatalf("levels=%d sig %d: %v", levels, i, err)
			}
			if len(sig) != HSSSignatureSize(h5w4(levels)) {
				t.Fatalf("size %d", len(sig))
			}
			if err := VerifyHSS(pub, msg, sig); err != nil {
				t.Fatalf("levels=%d sig %d: %v", levels, i, err)
			}
			// The bottom-level leaf and its tree identifier must never repeat.
			bottom := sig[len(sig)-LMS_SHA256_M32_H5.SignatureSize(LMOTS_SHA256_N32_W4):]
			var key []byte
			if levels == 2 {
				key = append(key, sig[4+LMS_SHA256_M32_H5.SignatureSize(LMOTS_SHA256_N32_W4):][8:8+IdentifierSize]...)
			}
			key = append(key, bottom[:4]...)
			if seen[string(key)] {
				t.Fatalf("one-time key reused at signature %d", i)
			}
			seen[string(key)] = true
			if s.Remaining() != total-i-1 {
				t.Fatalf("remaining after %d: %d", i+1, s.Remaining())
			}
		}
		if _, err := s.Sign([]byte("one more")); !errors.Is(err, ErrExhausted) {
			t.Fatalf("levels=%d: exhausted key signed: %v", levels, err)
		}
	}
}

func TestStateIsPersistedBeforeSigning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := FileStore{Path: path}
	seed, id := randomKey(t)
	s, err := NewSigner(h5w4(2), seed, id, State{}, store)
	if err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKey()
	for i := 0; i < 40; i++ {
		if _, err := s.Sign([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Next[0] != 1 || saved.Next[1] != 8 {
		t.Fatalf("after 40 signatures the state is %v, want [1 8]", saved.Next)
	}
	// A restarted signer continues from the saved state with the same key.
	resumed, err := NewSigner(h5w4(2), seed, id, saved, store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resumed.PublicKey().Bytes(), pub.Bytes()) {
		t.Fatal("public key changed after restart")
	}
	sig, err := resumed.Sign([]byte("after restart"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyHSS(pub, []byte("after restart"), sig); err != nil {
		t.Fatal(err)
	}
	if q := binary.BigEndian.Uint32(sig[len(sig)-LMS_SHA256_M32_H5.SignatureSize(LMOTS_SHA256_N32_W4):]); q != 8 {
		t.Fatalf("resumed at leaf %d, want 8", q)
	}
}

type failingStore struct{}

func (failingStore) Save(State) error { return errors.New("disk full") }

func TestNoSignatureWithoutDurableState(t *testing.T) {
	seed, id := randomKey(t)
	s, err := NewSigner(h5w4(1), seed, id, State{}, failingStore{})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("x"))
	if err == nil || sig != nil {
		t.Fatal("signed without persisting state")
	}
	if s.State().Next[0] != 0 {
		t.Fatal("in-memory state advanced although persisting failed")
	}
}

func TestChildCertificationIsDeterministic(t *testing.T) {
	// Signing with the same state twice (e.g. after a crash before the
	// signature was delivered) must reproduce the exact same certification of
	// the child tree, so the parent leaf never signs two different messages.
	seed, id := randomKey(t)
	a, _ := NewSigner(h5w4(2), seed, id, State{Next: []uint32{3, 5}}, &MemoryStore{})
	b, _ := NewSigner(h5w4(2), seed, id, State{Next: []uint32{3, 5}}, &MemoryStore{})
	sa, _ := a.Sign([]byte("m1"))
	sb, _ := b.Sign([]byte("m2"))
	certLen := 4 + LMS_SHA256_M32_H5.SignatureSize(LMOTS_SHA256_N32_W4) + PublicKeySize
	if !bytes.Equal(sa[:certLen], sb[:certLen]) {
		t.Fatal("child certification differs between runs")
	}
}

func TestSignerRejectsBadState(t *testing.T) {
	seed, id := randomKey(t)
	if _, err := NewSigner(h5w4(2), seed, id, State{Next: []uint32{0}}, &MemoryStore{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("wrong level count: %v", err)
	}
	if _, err := NewSigner(h5w4(2), seed, id, State{Next: []uint32{0, 32}}, &MemoryStore{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("lower index at capacity: %v", err)
	}
	if _, err := NewSigner(nil, seed, id, State{}, &MemoryStore{}); err == nil {
		t.Error("zero levels accepted")
	}
	exhausted, err := NewSigner(h5w4(2), seed, id, State{Next: []uint32{32, 0}}, &MemoryStore{})
	if err != nil {
		t.Fatalf("exhausted key should still load: %v", err)
	}
	if exhausted.Remaining() != 0 {
		t.Fatal("exhausted key has remaining signatures")
	}
	if _, err := exhausted.Sign(nil); !errors.Is(err, ErrExhausted) {
		t.Fatal("exhausted key signed")
	}
}

func FuzzVerifyHSS(f *testing.F) {
	seed, id := randomKey(f)
	s, _ := NewSigner(h5w4(2), seed, id, State{}, &MemoryStore{})
	pub := s.PublicKey()
	sig, _ := s.Sign([]byte("seed"))
	f.Add([]byte("seed"), sig)
	f.Add([]byte{}, []byte{0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, msg, sig []byte) {
		// Must never panic, and must reject anything except genuine signatures.
		err := VerifyHSS(pub, msg, sig)
		if err == nil && string(msg) != "seed" {
			t.Fatalf("forged signature accepted for %q", msg)
		}
	})
}
