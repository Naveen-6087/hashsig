package slhdsa

import (
	"bytes"
	"errors"
	"testing"
)

func TestParamSetsAndSizes(t *testing.T) {
	sets := ParamSets()
	if len(sets) != 12 {
		t.Fatalf("want 12 FIPS 205 parameter sets, got %d", len(sets))
	}
	// FIPS 205 Table 2.
	want := map[Params][3]int{
		"SLH-DSA-SHA2-128s":  {32, 64, 7856},
		"SLH-DSA-SHA2-128f":  {32, 64, 17088},
		"SLH-DSA-SHAKE-192s": {48, 96, 16224},
		"SLH-DSA-SHAKE-256f": {64, 128, 49856},
	}
	for p, w := range want {
		pub, priv, sig, err := p.Sizes()
		if err != nil || [3]int{pub, priv, sig} != w {
			t.Errorf("%s: got %d/%d/%d (%v), want %v", p, pub, priv, sig, err, w)
		}
	}
	if _, _, _, err := Params("SLH-DSA-MD5-1").Sizes(); !errors.Is(err, ErrUnknownParams) {
		t.Errorf("unknown set: %v", err)
	}
}

func TestRoundTripHedgedAndDeterministic(t *testing.T) {
	p := Params("SLH-DSA-SHAKE-128f")
	pub, priv, err := GenerateKey(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, ctx := []byte("lean consensus"), []byte("app-v1")
	hedged1, _ := Sign(p, priv, msg, ctx, false)
	hedged2, _ := Sign(p, priv, msg, ctx, false)
	if bytes.Equal(hedged1, hedged2) {
		t.Error("hedged signatures should differ")
	}
	det1, _ := Sign(p, priv, msg, ctx, true)
	det2, _ := Sign(p, priv, msg, ctx, true)
	if !bytes.Equal(det1, det2) {
		t.Error("deterministic signatures should match")
	}
	for _, sig := range [][]byte{hedged1, hedged2, det1} {
		if err := Verify(p, pub, msg, sig, ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(p, pub, msg, det1, []byte("app-v2")); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong context accepted: %v", err)
	}
	if err := Verify(p, pub, append(msg, '!'), det1, ctx); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong message accepted: %v", err)
	}
	if err := Verify(p, pub, msg, det1[:len(det1)-1], ctx); !errors.Is(err, ErrInvalid) {
		t.Errorf("truncated signature accepted: %v", err)
	}
	long := bytes.Repeat([]byte{1}, 256)
	if _, err := Sign(p, priv, msg, long, true); !errors.Is(err, ErrContext) {
		t.Errorf("256-byte context: %v", err)
	}
	if err := Verify(p, pub[:10], msg, det1, ctx); err == nil {
		t.Error("short public key accepted")
	}
}
