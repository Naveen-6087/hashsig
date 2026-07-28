package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Naveen-6087/hashsig/lms"
)

// lmsKeyFile holds the top-level seed and identifier plus the tree shape. The
// state lives in its own file so the key can be backed up once while the
// state changes on every signature.
type lmsKeyFile struct {
	Levels []string `json:"levels"`
	Seed   string   `json:"seed"`
	I      string   `json:"i"`
}

// parseLevels accepts the short form "H10/W4,H5/W8", top level first.
func parseLevels(spec string) ([]lms.LevelParams, error) {
	var out []lms.LevelParams
	for _, part := range strings.Split(spec, ",") {
		h, w, ok := strings.Cut(strings.TrimSpace(part), "/")
		if !ok {
			return nil, fmt.Errorf("level %q: want H<height>/W<w>, e.g. H10/W4", part)
		}
		l, err := parseLevel("LMS_SHA256_M32_"+strings.ToUpper(h), "LMOTS_SHA256_N32_"+strings.ToUpper(w))
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func parseLevel(typ, ots string) (lms.LevelParams, error) {
	t, err := lms.ParseType(typ)
	if err != nil {
		return lms.LevelParams{}, err
	}
	o, err := lms.ParseOTSType(ots)
	if err != nil {
		return lms.LevelParams{}, err
	}
	return lms.LevelParams{Type: t, OTSType: o}, nil
}

func loadLMSKey(path string) (levels []lms.LevelParams, seed [lms.N]byte, id [lms.IdentifierSize]byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var kf lmsKeyFile
	if err = json.Unmarshal(data, &kf); err != nil {
		err = fmt.Errorf("key file: %w", err)
		return
	}
	for _, s := range kf.Levels {
		t, o, _ := strings.Cut(s, "/")
		var l lms.LevelParams
		if l, err = parseLevel(t, o); err != nil {
			return
		}
		levels = append(levels, l)
	}
	s, e1 := hex.DecodeString(kf.Seed)
	i, e2 := hex.DecodeString(kf.I)
	if e1 != nil || e2 != nil || len(s) != lms.N || len(i) != lms.IdentifierSize {
		err = errors.New("key file: bad seed or identifier")
		return
	}
	copy(seed[:], s)
	copy(id[:], i)
	return
}

func defaultState(key, state string) string {
	if state != "" {
		return state
	}
	return strings.TrimSuffix(key, ".key") + ".state"
}

func openSigner(keyPath, statePath string) (*lms.Signer, error) {
	levels, seed, id, err := loadLMSKey(keyPath)
	if err != nil {
		return nil, err
	}
	store := lms.FileStore{Path: statePath}
	state, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return lms.NewSigner(levels, seed, id, state, store)
}

func (c cli) lmsKeygen(args []string) error {
	fs := flag.NewFlagSet("lms keygen", flag.ContinueOnError)
	levelSpec := fs.String("levels", "H10/W4,H10/W4", "comma-separated tree levels, top first")
	prefix := fs.String("out", "lms", "writes <out>.key, <out>.state and <out>.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	levels, err := parseLevels(*levelSpec)
	if err != nil {
		return err
	}
	var seed [lms.N]byte
	var id [lms.IdentifierSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	s, err := lms.NewSigner(levels, seed, id, lms.State{}, &lms.MemoryStore{})
	if err != nil {
		return err
	}
	kf := lmsKeyFile{Seed: hex.EncodeToString(seed[:]), I: hex.EncodeToString(id[:])}
	for _, l := range levels {
		kf.Levels = append(kf.Levels, l.String())
	}
	keyJSON, _ := json.MarshalIndent(kf, "", "  ")
	stateJSON, _ := json.Marshal(s.State())
	if err := writeNew(*prefix+".key", keyJSON, 0o600); err != nil {
		return err
	}
	if err := writeNew(*prefix+".state", stateJSON, 0o600); err != nil {
		return err
	}
	if err := writeNew(*prefix+".pub", s.PublicKey().Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "levels      %s\nsignatures  %d\nsig size    %d bytes\npublic key  %x\n",
		strings.Join(kf.Levels, ", "), s.Remaining(), lms.HSSSignatureSize(levels), s.PublicKey().Bytes())
	return nil
}

func (c cli) lmsSign(args []string) error {
	fs := flag.NewFlagSet("lms sign", flag.ContinueOnError)
	key := fs.String("key", "lms.key", "private key file")
	state := fs.String("state", "", "state file (default <key>.state)")
	in := fs.String("in", "-", "message file, - for stdin")
	sigOut := fs.String("sig", "", "signature output file (default: hex to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	msg, err := c.readInput(*in)
	if err != nil {
		return err
	}
	s, err := openSigner(*key, defaultState(*key, *state))
	if err != nil {
		return err
	}
	sig, err := s.Sign(msg)
	if err != nil {
		return err
	}
	return c.writeSig(*sigOut, sig)
}

// readSig accepts raw bytes or a hex string.
func readSig(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if h, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil {
		return h, nil
	}
	return b, nil
}

func (c cli) lmsVerify(args []string) error {
	fs := flag.NewFlagSet("lms verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "lms.pub", "public key file")
	in := fs.String("in", "-", "message file, - for stdin")
	sigPath := fs.String("sig", "", "signature file (raw or hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pubBytes, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := lms.ParseHSSPublicKey(pubBytes)
	if err != nil {
		return err
	}
	msg, err := c.readInput(*in)
	if err != nil {
		return err
	}
	sig, err := readSig(*sigPath)
	if err != nil {
		return err
	}
	if err := lms.VerifyHSS(pub, msg, sig); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "OK")
	return nil
}

func (c cli) lmsInfo(args []string) error {
	fs := flag.NewFlagSet("lms info", flag.ContinueOnError)
	key := fs.String("key", "lms.key", "private key file")
	state := fs.String("state", "", "state file (default <key>.state)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := openSigner(*key, defaultState(*key, *state))
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "state       %v\nremaining   %d\npublic key  %x\n", s.State().Next, s.Remaining(), s.PublicKey().Bytes())
	return nil
}
