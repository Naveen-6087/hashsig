package lms

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
)

// PublicKey is an LMS public key: u32str(type) || u32str(otstype) || I || T[1].
type PublicKey struct {
	Type    Type
	OTSType OTSType
	I       [IdentifierSize]byte
	Root    [N]byte
}

func (pk PublicKey) Bytes() []byte {
	out := append(u32(uint32(pk.Type)), u32(uint32(pk.OTSType))...)
	out = append(out, pk.I[:]...)
	return append(out, pk.Root[:]...)
}

func ParsePublicKey(b []byte) (PublicKey, error) {
	var pk PublicKey
	if len(b) != PublicKeySize {
		return pk, fmt.Errorf("%w: LMS public key is %d bytes, want %d", ErrMalformed, len(b), PublicKeySize)
	}
	pk.Type = Type(binary.BigEndian.Uint32(b))
	pk.OTSType = OTSType(binary.BigEndian.Uint32(b[4:]))
	if _, err := pk.Type.Height(); err != nil {
		return pk, err
	}
	if _, err := pk.OTSType.params(); err != nil {
		return pk, err
	}
	copy(pk.I[:], b[8:])
	copy(pk.Root[:], b[8+IdentifierSize:])
	return pk, nil
}

// Tree is an LMS private key with its full Merkle tree kept in memory
// (2^(h+1) nodes), so signing only has to read an authentication path.
type Tree struct {
	pub   PublicKey
	seed  [N]byte
	nodes [][N]byte // nodes[r] = T[r], r in [1, 2^(h+1))
	h     uint
}

func leafHash(id []byte, r uint32, k []byte) [N]byte {
	h := sha256.New()
	h.Write(id)
	h.Write(u32(r))
	h.Write(u16(dLEAF))
	h.Write(k)
	var out [N]byte
	h.Sum(out[:0])
	return out
}

func interiorHash(id []byte, r uint32, left, right []byte) [N]byte {
	h := sha256.New()
	h.Write(id)
	h.Write(u32(r))
	h.Write(u16(dINTR))
	h.Write(left)
	h.Write(right)
	var out [N]byte
	h.Sum(out[:0])
	return out
}

// NewTree derives an LMS key from SEED and I using the pseudorandom key
// generation of RFC 8554 Appendix A. Leaf public keys are computed in parallel.
func NewTree(t Type, ots OTSType, seed [N]byte, id [IdentifierSize]byte) (*Tree, error) {
	h, err := t.Height()
	if err != nil {
		return nil, err
	}
	if _, err := ots.params(); err != nil {
		return nil, err
	}
	leaves := uint32(1) << h
	nodes := make([][N]byte, 2*leaves)

	workers := min(runtime.GOMAXPROCS(0), int(leaves))
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for q := uint32(w); q < leaves; q += uint32(workers) {
				k, err := otsPublicKey(ots, seed[:], id[:], q)
				if err != nil {
					errs[w] = err
					return
				}
				nodes[leaves+q] = leafHash(id[:], leaves+q, k)
			}
		}(w)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	for r := leaves - 1; r >= 1; r-- {
		nodes[r] = interiorHash(id[:], r, nodes[2*r][:], nodes[2*r+1][:])
	}
	return &Tree{pub: PublicKey{Type: t, OTSType: ots, I: id, Root: nodes[1]}, seed: seed, nodes: nodes, h: h}, nil
}

func (t *Tree) PublicKey() PublicKey { return t.pub }

// Capacity is the number of one-time keys, 2^h.
func (t *Tree) Capacity() uint32 { return 1 << t.h }

// SignAt signs msg with one-time key q and randomizer c. It does not track
// state: callers must never use the same q twice (see Signer and FileState).
func (t *Tree) SignAt(q uint32, c, msg []byte) ([]byte, error) {
	if q >= t.Capacity() {
		return nil, ErrExhausted
	}
	otsSig, err := otsSign(t.pub.OTSType, t.seed[:], t.pub.I[:], q, c, msg)
	if err != nil {
		return nil, err
	}
	sig := append(u32(q), otsSig...)
	sig = append(sig, u32(uint32(t.pub.Type))...)
	r := t.Capacity() + q
	for i := uint(0); i < t.h; i++ {
		sibling := (r >> i) ^ 1
		sig = append(sig, t.nodes[sibling][:]...)
	}
	return sig, nil
}

// Verify checks an LMS signature (RFC 8554 Algorithms 6 and 6a).
func Verify(pub PublicKey, msg, sig []byte) error {
	root, err := candidateRoot(pub, msg, sig)
	if err != nil {
		return err
	}
	if !bytes.Equal(root[:], pub.Root[:]) {
		return ErrInvalid
	}
	return nil
}

func candidateRoot(pub PublicKey, msg, sig []byte) ([N]byte, error) {
	var zero [N]byte
	h, err := pub.Type.Height()
	if err != nil {
		return zero, err
	}
	otsLen := pub.OTSType.SignatureSize()
	if otsLen == 0 {
		return zero, fmt.Errorf("%w: LM-OTS type %d", ErrUnsupportedType, uint32(pub.OTSType))
	}
	if len(sig) != pub.Type.SignatureSize(pub.OTSType) {
		return zero, fmt.Errorf("%w: LMS signature is %d bytes, want %d", ErrMalformed, len(sig), pub.Type.SignatureSize(pub.OTSType))
	}
	q := binary.BigEndian.Uint32(sig)
	if uint64(q) >= uint64(1)<<h {
		return zero, fmt.Errorf("%w: leaf index %d out of range", ErrMalformed, q)
	}
	otsSig := sig[4 : 4+otsLen]
	if OTSType(binary.BigEndian.Uint32(otsSig)) != pub.OTSType {
		return zero, fmt.Errorf("%w: LM-OTS type does not match the public key", ErrMalformed)
	}
	rest := sig[4+otsLen:]
	if Type(binary.BigEndian.Uint32(rest)) != pub.Type {
		return zero, fmt.Errorf("%w: LMS type does not match the public key", ErrMalformed)
	}
	path := rest[4:]

	_, kc, err := otsCandidate(otsSig, pub.I[:], q, msg)
	if err != nil {
		return zero, err
	}
	node := (uint32(1) << h) + q
	tmp := leafHash(pub.I[:], node, kc)
	for i := uint(0); node > 1; i++ {
		sibling := path[i*N : (i+1)*N]
		if node&1 == 1 {
			tmp = interiorHash(pub.I[:], node/2, sibling, tmp[:])
		} else {
			tmp = interiorHash(pub.I[:], node/2, tmp[:], sibling)
		}
		node /= 2
	}
	return tmp, nil
}
