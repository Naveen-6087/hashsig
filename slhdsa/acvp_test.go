package slhdsa

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The NIST ACVP vectors for FIPS 205 ship with circl
// (sign/slhdsa/testdata, from usnistgov/ACVP-Server). They are read from the
// module cache rather than copied, since the signing vectors alone are 18 MB.
func acvpDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/cloudflare/circl").Output()
	if err != nil {
		t.Fatalf("locating circl: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "sign", "slhdsa", "testdata")
}

func readGz(t *testing.T, name string, v any) {
	t.Helper()
	f, err := os.Open(filepath.Join(acvpDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatal(err)
	}
}

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

func TestACVPKeyGen(t *testing.T) {
	var prompt struct {
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID   int      `json:"tcId"`
				SkSeed hexBytes `json:"skSeed"`
				SkPrf  hexBytes `json:"skPrf"`
				PkSeed hexBytes `json:"pkSeed"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	var result struct {
		TestGroups []struct {
			Tests []struct {
				TcID int      `json:"tcId"`
				Sk   hexBytes `json:"sk"`
				Pk   hexBytes `json:"pk"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	readGz(t, "keyGen_prompt.json.gz", &prompt)
	readGz(t, "keyGen_results.json.gz", &result)
	n := 0
	for gi, g := range prompt.TestGroups {
		for ti, tc := range g.Tests {
			want := result.TestGroups[gi].Tests[ti]
			if want.TcID != tc.TcID {
				t.Fatalf("tcId mismatch %d/%d", tc.TcID, want.TcID)
			}
			seed := bytes.NewReader(append(append(append([]byte{}, tc.SkSeed...), tc.SkPrf...), tc.PkSeed...))
			pub, priv, err := GenerateKey(Params(g.ParameterSet), seed)
			if err != nil {
				t.Fatalf("%s tc %d: %v", g.ParameterSet, tc.TcID, err)
			}
			if !bytes.Equal(pub, want.Pk) || !bytes.Equal(priv, want.Sk) {
				t.Fatalf("%s tc %d: keys differ", g.ParameterSet, tc.TcID)
			}
			n++
		}
	}
	if n != 120 {
		t.Fatalf("ran %d keyGen cases, want 120", n)
	}
}

func TestACVPSigVer(t *testing.T) {
	var prompt struct {
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Interface    string `json:"signatureInterface"`
			PreHash      string `json:"preHash"`
			Tests        []struct {
				TcID int      `json:"tcId"`
				Pk   hexBytes `json:"pk"`
				Msg  hexBytes `json:"message"`
				Sig  hexBytes `json:"signature"`
				Ctx  hexBytes `json:"context"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	var result struct {
		TestGroups []struct {
			Tests []struct {
				TcID   int  `json:"tcId"`
				Passed bool `json:"testPassed"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	readGz(t, "verify_prompt.json.gz", &prompt)
	readGz(t, "verify_results.json.gz", &result)
	n, rejected := 0, 0
	for gi, g := range prompt.TestGroups {
		if g.Interface != "external" || g.PreHash != "pure" {
			continue
		}
		for ti, tc := range g.Tests {
			want := result.TestGroups[gi].Tests[ti]
			err := Verify(Params(g.ParameterSet), tc.Pk, tc.Msg, tc.Sig, tc.Ctx)
			if (err == nil) != want.Passed {
				t.Errorf("%s tc %d: verify=%v, expected pass=%v", g.ParameterSet, tc.TcID, err, want.Passed)
			}
			if !want.Passed {
				rejected++
			}
			n++
		}
	}
	if n != 168 || rejected == 0 {
		t.Fatalf("ran %d sigVer cases (%d expected failures), want 168 with some failures", n, rejected)
	}
}

// Slow "s" parameter sets are only signed when HASHSIG_FULL_ACVP=1.
func TestACVPSigGen(t *testing.T) {
	var prompt struct {
		TestGroups []struct {
			ParameterSet  string `json:"parameterSet"`
			Interface     string `json:"signatureInterface"`
			PreHash       string `json:"preHash"`
			Deterministic bool   `json:"deterministic"`
			Tests         []struct {
				TcID    int      `json:"tcId"`
				Sk      hexBytes `json:"sk"`
				Msg     hexBytes `json:"message"`
				Ctx     hexBytes `json:"context"`
				AddRand hexBytes `json:"additionalRandomness"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	var result struct {
		TestGroups []struct {
			Tests []struct {
				TcID int      `json:"tcId"`
				Sig  hexBytes `json:"signature"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	readGz(t, "sigGen_prompt.json.gz", &prompt)
	readGz(t, "sigGen_results.json.gz", &result)
	full := os.Getenv("HASHSIG_FULL_ACVP") == "1"
	n := 0
	for gi, g := range prompt.TestGroups {
		if g.Interface != "external" || g.PreHash != "pure" {
			continue
		}
		if strings.HasSuffix(g.ParameterSet, "s") && !full {
			continue
		}
		for ti, tc := range g.Tests {
			want := result.TestGroups[gi].Tests[ti].Sig
			sig, err := sign(Params(g.ParameterSet), tc.Sk, tc.Msg, tc.Ctx, g.Deterministic, bytes.NewReader(tc.AddRand))
			if err != nil {
				t.Fatalf("%s tc %d: %v", g.ParameterSet, tc.TcID, err)
			}
			if !bytes.Equal(sig, want) {
				t.Fatalf("%s tc %d (deterministic=%v): signature differs", g.ParameterSet, tc.TcID, g.Deterministic)
			}
			n++
		}
	}
	wantN := 84
	if full {
		wantN = 168
	}
	if n != wantN {
		t.Fatalf("ran %d sigGen cases, want %d", n, wantN)
	}
}
