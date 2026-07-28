package slhdsa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"

	circl "github.com/cloudflare/circl/sign/slhdsa"
)

var (
	ErrUnknownParams = errors.New("slhdsa: unknown parameter set")
	ErrInvalid       = errors.New("slhdsa: signature does not verify")
	ErrContext       = errors.New("slhdsa: context longer than 255 bytes")
)

// MaxContextSize is the FIPS 205 limit on the context string.
const MaxContextSize = 255

// Params names an FIPS 205 parameter set, e.g. "SLH-DSA-SHA2-128s".
type Params string

func (p Params) id() (circl.ID, error) {
	id, err := circl.IDByName(string(p))
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrUnknownParams, string(p))
	}
	return id, nil
}

// ParamSets lists the twelve FIPS 205 parameter sets.
func ParamSets() []Params {
	var out []Params
	for id := circl.ID(1); id.IsValid(); id++ {
		out = append(out, Params(id.String()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Sizes returns the public key, private key and signature sizes in bytes.
func (p Params) Sizes() (pub, priv, sig int, err error) {
	id, err := p.id()
	if err != nil {
		return 0, 0, 0, err
	}
	s := id.Scheme()
	return s.PublicKeySize(), s.PrivateKeySize(), s.SignatureSize(), nil
}

// GenerateKey returns encoded keys. rng may be nil for crypto/rand.
func GenerateKey(p Params, rng io.Reader) (pub, priv []byte, err error) {
	id, err := p.id()
	if err != nil {
		return nil, nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	pk, sk, err := circl.GenerateKey(rng, id)
	if err != nil {
		return nil, nil, err
	}
	if pub, err = pk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	if priv, err = sk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Sign signs msg with the pure (non-prehash) FIPS 205 interface and the given
// context. Deterministic signing uses no fresh randomness (FIPS 205 allows
// both); hedged signing is the default recommendation.
func Sign(p Params, priv, msg, ctx []byte, deterministic bool) ([]byte, error) {
	return sign(p, priv, msg, ctx, deterministic, rand.Reader)
}

func sign(p Params, priv, msg, ctx []byte, deterministic bool, rng io.Reader) ([]byte, error) {
	id, err := p.id()
	if err != nil {
		return nil, err
	}
	if len(ctx) > MaxContextSize {
		return nil, ErrContext
	}
	sk := circl.PrivateKey{ID: id}
	if err := sk.UnmarshalBinary(priv); err != nil {
		return nil, fmt.Errorf("slhdsa: private key: %w", err)
	}
	m := circl.NewMessage(msg)
	if deterministic {
		return circl.SignDeterministic(&sk, m, ctx)
	}
	return circl.SignRandomized(&sk, rng, m, ctx)
}

// Verify checks a pure-interface signature.
func Verify(p Params, pub, msg, sig, ctx []byte) error {
	id, err := p.id()
	if err != nil {
		return err
	}
	if len(ctx) > MaxContextSize {
		return ErrContext
	}
	pk := circl.PublicKey{ID: id}
	if err := pk.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("slhdsa: public key: %w", err)
	}
	if !circl.Verify(&pk, circl.NewMessage(msg), sig, ctx) {
		return ErrInvalid
	}
	return nil
}
