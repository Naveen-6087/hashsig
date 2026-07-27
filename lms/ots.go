package lms

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

// coef returns the i-th w-bit digit of s (RFC 8554 section 3.1.3).
func coef(s []byte, i int, w uint) byte {
	mask := byte(1<<w - 1)
	perByte := 8 / int(w)
	b := s[i*int(w)/8]
	shift := 8 - (w*uint(i%perByte) + w)
	return (b >> shift) & mask
}

// checksum is Cksm(Q) from RFC 8554 section 4.4, left-shifted by ls.
func checksum(q []byte, p otsParams) uint16 {
	var sum uint16
	u := 8 * N / int(p.w)
	for i := 0; i < u; i++ {
		sum += uint16(1<<p.w-1) - uint16(coef(q, i, p.w))
	}
	return sum << p.ls
}

// digits returns the p chain lengths a_i for message digest q.
func digits(q []byte, p otsParams) []byte {
	ext := append(append([]byte{}, q...), u16(checksum(q, p))...)
	out := make([]byte, p.p)
	for i := range out {
		out[i] = coef(ext, i, p.w)
	}
	return out
}

// chain hashes tmp from step `from` up to (excluding) `to`:
// tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp).
func chain(h hash.Hash, id []byte, q uint32, i int, tmp []byte, from, to int) []byte {
	var prefix [IdentifierSize + 4 + 2 + 1]byte
	copy(prefix[:], id)
	binary.BigEndian.PutUint32(prefix[IdentifierSize:], q)
	binary.BigEndian.PutUint16(prefix[IdentifierSize+4:], uint16(i))
	out := append([]byte{}, tmp...)
	for j := from; j < to; j++ {
		prefix[IdentifierSize+6] = byte(j)
		h.Reset()
		h.Write(prefix[:])
		h.Write(out)
		out = h.Sum(out[:0])
	}
	return out
}

// otsPrivate derives the p secret chain starts from SEED (RFC 8554 Appendix A):
// x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
func otsPrivate(seed, id []byte, q uint32, p otsParams) [][]byte {
	h := sha256.New()
	x := make([][]byte, p.p)
	for i := range x {
		h.Reset()
		h.Write(id)
		h.Write(u32(q))
		h.Write(u16(uint16(i)))
		h.Write([]byte{0xff})
		h.Write(seed)
		x[i] = h.Sum(nil)
	}
	return x
}

// otsPublicKey computes K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]).
func otsPublicKey(t OTSType, seed, id []byte, q uint32) ([]byte, error) {
	p, err := t.params()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	outer := sha256.New()
	outer.Write(id)
	outer.Write(u32(q))
	outer.Write(u16(dPBLC))
	for i, x := range otsPrivate(seed, id, q, p) {
		outer.Write(chain(h, id, q, i, x, 0, 1<<p.w-1))
	}
	return outer.Sum(nil), nil
}

func messageDigest(id []byte, q uint32, c, msg []byte) []byte {
	h := sha256.New()
	h.Write(id)
	h.Write(u32(q))
	h.Write(u16(dMESG))
	h.Write(c)
	h.Write(msg)
	return h.Sum(nil)
}

// otsSign produces u32str(type) || C || y[0] || ... || y[p-1] with randomizer c.
func otsSign(t OTSType, seed, id []byte, q uint32, c, msg []byte) ([]byte, error) {
	p, err := t.params()
	if err != nil {
		return nil, err
	}
	if len(c) != N {
		return nil, fmt.Errorf("lms: randomizer must be %d bytes", N)
	}
	a := digits(messageDigest(id, q, c, msg), p)
	sig := append(u32(uint32(t)), c...)
	h := sha256.New()
	for i, x := range otsPrivate(seed, id, q, p) {
		sig = append(sig, chain(h, id, q, i, x, 0, int(a[i]))...)
	}
	return sig, nil
}

// otsCandidate computes the candidate public key Kc from a signature
// (RFC 8554 Algorithm 4b). The caller checks that the type matches the key.
func otsCandidate(sig, id []byte, q uint32, msg []byte) (OTSType, []byte, error) {
	if len(sig) < 4 {
		return 0, nil, fmt.Errorf("%w: LM-OTS signature too short", ErrMalformed)
	}
	t := OTSType(binary.BigEndian.Uint32(sig))
	p, err := t.params()
	if err != nil {
		return 0, nil, err
	}
	if len(sig) != t.SignatureSize() {
		return 0, nil, fmt.Errorf("%w: LM-OTS signature is %d bytes, want %d", ErrMalformed, len(sig), t.SignatureSize())
	}
	c := sig[4 : 4+N]
	ys := sig[4+N:]
	a := digits(messageDigest(id, q, c, msg), p)
	h := sha256.New()
	outer := sha256.New()
	outer.Write(id)
	outer.Write(u32(q))
	outer.Write(u16(dPBLC))
	for i := 0; i < p.p; i++ {
		outer.Write(chain(h, id, q, i, ys[i*N:(i+1)*N], int(a[i]), 1<<p.w-1))
	}
	return t, outer.Sum(nil), nil
}
