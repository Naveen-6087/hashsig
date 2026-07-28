package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestLMSWorkflow(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "k")
	out, err := runCLI(t, "", "lms", "keygen", "-levels", "H5/W4,H5/W8", "-out", prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "signatures  1024") {
		t.Fatalf("keygen output:\n%s", out)
	}
	if _, err := runCLI(t, "", "lms", "keygen", "-out", prefix); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}

	msgPath := filepath.Join(dir, "msg")
	os.WriteFile(msgPath, []byte("block 1"), 0o644)
	sigPath := filepath.Join(dir, "sig")
	for i := 0; i < 3; i++ {
		if _, err := runCLI(t, "", "lms", "sign", "-key", prefix+".key", "-in", msgPath, "-sig", sigPath); err != nil {
			t.Fatal(err)
		}
	}
	out, err = runCLI(t, "", "lms", "verify", "-pub", prefix+".pub", "-in", msgPath, "-sig", sigPath)
	if err != nil || strings.TrimSpace(out) != "OK" {
		t.Fatalf("verify: %q %v", out, err)
	}
	if _, err := runCLI(t, "tampered", "lms", "verify", "-pub", prefix+".pub", "-sig", sigPath); err == nil {
		t.Fatal("tampered message verified")
	}
	out, err = runCLI(t, "", "lms", "info", "-key", prefix+".key")
	if err != nil || !strings.Contains(out, "state       [0 3]") || !strings.Contains(out, "remaining   1021") {
		t.Fatalf("info:\n%s %v", out, err)
	}

	hexSig, err := runCLI(t, "from stdin", "lms", "sign", "-key", prefix+".key")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(sigPath, []byte(hexSig), 0o644)
	if _, err := runCLI(t, "from stdin", "lms", "verify", "-pub", prefix+".pub", "-sig", sigPath); err != nil {
		t.Fatalf("hex signature: %v", err)
	}
}

func TestSLHWorkflow(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "s")
	if _, err := runCLI(t, "", "slh", "keygen", "-params", "SLH-DSA-SHAKE-128f", "-out", prefix); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "sig")
	if _, err := runCLI(t, "payload", "slh", "sign", "-key", prefix+".key", "-ctx", "v1", "-sig", sigPath); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, "payload", "slh", "verify", "-pub", prefix+".pub", "-ctx", "v1", "-sig", sigPath); err != nil || strings.TrimSpace(out) != "OK" {
		t.Fatalf("verify: %q %v", out, err)
	}
	if _, err := runCLI(t, "payload", "slh", "verify", "-pub", prefix+".pub", "-ctx", "v2", "-sig", sigPath); err == nil {
		t.Fatal("wrong context verified")
	}
	if _, err := runCLI(t, "", "slh", "keygen", "-params", "SLH-DSA-FOO", "-out", filepath.Join(dir, "x")); err == nil {
		t.Fatal("unknown parameter set accepted")
	}
}

func TestParamsAndErrors(t *testing.T) {
	out, err := runCLI(t, "", "params")
	if err != nil || !strings.Contains(out, "SLH-DSA-SHA2-128s") || !strings.Contains(out, "LMS_SHA256_M32_H25/W8") {
		t.Fatalf("params:\n%s %v", out, err)
	}
	if _, err := runCLI(t, "", "nope"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if _, err := runCLI(t, "", "lms", "keygen", "-levels", "H7/W4"); err == nil {
		t.Fatal("H7 accepted")
	}
}
