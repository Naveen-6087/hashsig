package lms

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

// Domain constants for this package's derivations (not part of RFC 8554).
const (
	deriveChildSeed  = 0x01
	deriveChildI     = 0x02
	deriveRandomizer = 0x03
)

// State records, for every HSS level, the index of the next unused one-time
// key in that level's current tree.
type State struct {
	Next []uint32 `json:"next"`
}

func (s State) clone() State { return State{Next: append([]uint32(nil), s.Next...)} }

// StateStore persists the state. Save must be durable before it returns:
// the signer reserves a one-time key by saving, and only then signs.
type StateStore interface {
	Save(State) error
}

// MemoryStore keeps state in memory only. Use it for tests and benchmarks;
// a crash loses the state and makes key reuse possible.
type MemoryStore struct{ Last State }

func (m *MemoryStore) Save(s State) error {
	m.Last = s.clone()
	return nil
}

// Signer is a stateful HSS private key.
//
// The top-level tree is (SEED, I) as given. The tree certified by leaf q of a
// parent tree uses SEED' = H(SEED || I || u32str(q) || 0x01) and
// I' = H(SEED || I || u32str(q) || 0x02)[:16]. RFC 8554 leaves child key
// generation to implementations; deriving children deterministically means a
// parent's signature over a child key is identical every time it is
// produced, so restarting never signs a second message with that leaf.
type Signer struct {
	mu     sync.Mutex
	levels []LevelParams
	seed   [N]byte
	id     [IdentifierSize]byte
	state  State
	store  StateStore
	trees  []*Tree // the current tree at each level

	// durable is the last state written to the store. Leaves between state
	// and durable are reserved: they may be signed with without saving again.
	durable State
	reserve uint64
}

// NewSigner builds a signer resuming from state (use State{} for a new key).
func NewSigner(levels []LevelParams, seed [N]byte, id [IdentifierSize]byte, state State, store StateStore) (*Signer, error) {
	if len(levels) < 1 || len(levels) > MaxLevels {
		return nil, fmt.Errorf("%w: %d levels", ErrUnsupportedType, len(levels))
	}
	if len(state.Next) == 0 {
		state.Next = make([]uint32, len(levels))
	}
	if len(state.Next) != len(levels) {
		return nil, fmt.Errorf("%w: state has %d levels, key has %d", ErrMalformed, len(state.Next), len(levels))
	}
	if store == nil {
		return nil, errors.New("lms: a state store is required")
	}
	s := &Signer{levels: levels, seed: seed, id: id, state: state.clone(), durable: state.clone(), store: store, reserve: 1}
	if err := s.loadTrees(); err != nil {
		return nil, err
	}
	return s, nil
}

func childDerivation(seed [N]byte, id [IdentifierSize]byte, q uint32, label byte) [N]byte {
	h := sha256.New()
	h.Write(seed[:])
	h.Write(id[:])
	h.Write(u32(q))
	h.Write([]byte{label})
	var out [N]byte
	h.Sum(out[:0])
	return out
}

func (s *Signer) capacity(l int) uint32 {
	h, _ := s.levels[l].Type.Height()
	return 1 << h
}

func (s *Signer) exhausted() bool {
	return s.state.Next[0] >= s.capacity(0)
}

// loadTrees rebuilds the current tree at every level. An exhausted key keeps
// only its top tree, which is enough for its public key.
func (s *Signer) loadTrees() error {
	for l := range s.levels {
		if s.state.Next[l] > s.capacity(l) || (l > 0 && s.state.Next[l] == s.capacity(l)) {
			return fmt.Errorf("%w: level %d index %d out of range", ErrMalformed, l, s.state.Next[l])
		}
	}
	s.trees = make([]*Tree, len(s.levels))
	seed, id := s.seed, s.id
	for l, params := range s.levels {
		tree, err := NewTree(params.Type, params.OTSType, seed, id)
		if err != nil {
			return err
		}
		s.trees[l] = tree
		q := s.state.Next[l]
		if l+1 == len(s.levels) || q == tree.Capacity() {
			break
		}
		// The child tree is the one certified by the parent's current leaf.
		childID := childDerivation(seed, id, q, deriveChildI)
		seed = childDerivation(seed, id, q, deriveChildSeed)
		copy(id[:], childID[:IdentifierSize])
	}
	return nil
}

func (s *Signer) PublicKey() HSSPublicKey {
	return HSSPublicKey{Levels: uint32(len(s.levels)), Top: s.trees[0].PublicKey()}
}

func (s *Signer) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.clone()
}

// Remaining is the number of messages that can still be signed: the total
// number of bottom-level leaves minus the position of the next one.
func (s *Signer) Remaining() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := s.total()
	return total - min(s.position(s.state), total)
}

// SetReservation makes the signer persist its state once per n signatures
// instead of before every one. Each save reserves the next n one-time keys,
// so a crash wastes up to n-1 of them but can never reuse one. Call Release
// on shutdown to hand back the unused part of the reservation.
func (s *Signer) SetReservation(n uint64) error {
	if n == 0 {
		return errors.New("lms: reservation must be at least 1")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reserve = n
	return nil
}

// Release saves the exact current state, returning reserved but unused
// one-time keys. The signer remains usable afterwards.
func (s *Signer) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.position(s.durable) == s.position(s.state) {
		return nil
	}
	if err := s.store.Save(s.state); err != nil {
		return err
	}
	s.durable = s.state.clone()
	return nil
}

func (s *Signer) total() uint64 {
	total := uint64(1)
	for l := range s.levels {
		total *= uint64(s.capacity(l))
	}
	return total
}

// position is the index of the next bottom-level leaf across the whole key.
func (s *Signer) position(st State) uint64 {
	pos, mult := uint64(0), uint64(1)
	for l := len(s.levels) - 1; l >= 0; l-- {
		pos += uint64(st.Next[l]) * mult
		mult *= uint64(s.capacity(l))
	}
	return pos
}

// stateAt is the inverse of position; an exhausted key is [cap 0 ... 0].
func (s *Signer) stateAt(pos uint64) State {
	st := State{Next: make([]uint32, len(s.levels))}
	for l := len(s.levels) - 1; l > 0; l-- {
		c := uint64(s.capacity(l))
		st.Next[l] = uint32(pos % c)
		pos /= c
	}
	st.Next[0] = uint32(pos)
	return st
}

// Sign reserves the next one-time key, persists the reservation unless it
// is already covered by an earlier one, and only then produces the HSS
// signature.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bottom := len(s.levels) - 1
	if s.exhausted() {
		return nil, ErrExhausted
	}
	used := s.state.clone()
	pos := s.position(used)
	next := s.stateAt(pos + 1)
	if pos >= s.position(s.durable) {
		reserved := s.stateAt(min(pos+s.reserve, s.total()))
		if err := s.store.Save(reserved); err != nil {
			return nil, fmt.Errorf("lms: persisting state before signing: %w", err)
		}
		s.durable = reserved
	}

	sig := u32(uint32(bottom))
	for l := 0; l < bottom; l++ {
		child := s.trees[l+1].PublicKey().Bytes()
		q := used.Next[l]
		part, err := s.trees[l].SignAt(q, s.randomizer(l, q), child)
		if err != nil {
			return nil, err
		}
		sig = append(append(sig, part...), child...)
	}
	q := used.Next[bottom]
	part, err := s.trees[bottom].SignAt(q, s.randomizer(bottom, q), msg)
	if err != nil {
		return nil, err
	}
	sig = append(sig, part...)

	s.state = next
	if !s.exhausted() && changedAbove(used, next) {
		if err := s.loadTrees(); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

func changedAbove(a, b State) bool {
	for l := 0; l < len(a.Next)-1; l++ {
		if a.Next[l] != b.Next[l] {
			return true
		}
	}
	return false
}

// randomizer derives C for leaf q of the current tree at level l from that
// tree's secret seed, so re-signing the same leaf reproduces the same signature.
func (s *Signer) randomizer(l int, q uint32) []byte {
	t := s.trees[l]
	c := childDerivation(t.seed, t.pub.I, q, deriveRandomizer)
	return c[:]
}
