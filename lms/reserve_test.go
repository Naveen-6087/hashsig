package lms

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
)

type countingStore struct {
	MemoryStore
	saves int
}

func (c *countingStore) Save(s State) error {
	c.saves++
	return c.MemoryStore.Save(s)
}

func bottomLeaf(sig []byte) uint32 {
	return binary.BigEndian.Uint32(sig[len(sig)-LMS_SHA256_M32_H5.SignatureSize(LMOTS_SHA256_N32_W4):])
}

func TestReservationBatchesSaves(t *testing.T) {
	seed, id := randomKey(t)
	store := &countingStore{}
	s, err := NewSigner(h5w4(2), seed, id, State{}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetReservation(0); err == nil {
		t.Fatal("zero reservation accepted")
	}
	if err := s.SetReservation(10); err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKey()
	for i := 0; i < 45; i++ {
		msg := []byte{byte(i)}
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyHSS(pub, msg, sig); err != nil {
			t.Fatalf("sig %d: %v", i, err)
		}
	}
	if store.saves != 5 {
		t.Fatalf("%d saves for 45 signatures with a reservation of 10, want 5", store.saves)
	}
	// The store is ahead of the signer: it covers all 50 reserved leaves.
	if got := store.Last.Next; got[0] != 1 || got[1] != 18 {
		t.Fatalf("stored state %v, want [1 18]", got)
	}
	if got := s.State().Next; got[0] != 1 || got[1] != 13 {
		t.Fatalf("in-memory state %v, want [1 13]", got)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if got := store.Last.Next; got[0] != 1 || got[1] != 13 || store.saves != 6 {
		t.Fatalf("after release: stored %v, saves %d", got, store.saves)
	}
	if err := s.Release(); err != nil || store.saves != 6 {
		t.Fatal("releasing twice saved again")
	}
}

func TestReservationSurvivesCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := FileStore{Path: path}
	seed, id := randomKey(t)
	s, _ := NewSigner(h5w4(2), seed, id, State{}, store)
	s.SetReservation(8)
	used := map[uint32]bool{}
	for i := 0; i < 3; i++ {
		sig, _ := s.Sign([]byte{byte(i)})
		used[bottomLeaf(sig)] = true
	}
	// Simulate a crash: drop the signer without Release and reload from disk.
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := NewSigner(h5w4(2), seed, id, saved, store)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := resumed.Sign([]byte("after crash"))
	if err != nil {
		t.Fatal(err)
	}
	if q := bottomLeaf(sig); used[q] || q != 8 {
		t.Fatalf("resumed at leaf %d, want 8 (leaves 3-7 are burnt, never reused)", q)
	}
}

func TestReservationNeverPassesExhaustion(t *testing.T) {
	seed, id := randomKey(t)
	store := &countingStore{}
	s, _ := NewSigner(h5w4(1), seed, id, State{}, store)
	s.SetReservation(1000)
	for i := 0; i < 32; i++ {
		if _, err := s.Sign([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if store.saves != 1 || store.Last.Next[0] != 32 {
		t.Fatalf("saves %d, stored %v", store.saves, store.Last.Next)
	}
	if _, err := s.Sign(nil); !errors.Is(err, ErrExhausted) {
		t.Fatal("signed past the end of the key")
	}
}

func TestReservationFailureSignsNothing(t *testing.T) {
	seed, id := randomKey(t)
	s, _ := NewSigner(h5w4(1), seed, id, State{}, failingStore{})
	s.SetReservation(16)
	if sig, err := s.Sign([]byte("x")); err == nil || sig != nil {
		t.Fatal("signed without a durable reservation")
	}
	if s.State().Next[0] != 0 {
		t.Fatal("state advanced although the reservation failed")
	}
}
