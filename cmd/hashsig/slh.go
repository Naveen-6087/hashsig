package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Naveen-6087/hashsig/lms"
	"github.com/Naveen-6087/hashsig/slhdsa"
)

func (c cli) params() error {
	tw := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLH-DSA (FIPS 205)\tpublic\tprivate\tsignature")
	for _, p := range slhdsa.ParamSets() {
		pub, priv, sig, err := p.Sizes()
		if err != nil {
			return err
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", p, pub, priv, sig)
	}
	fmt.Fprintln(tw, "\nLMS (RFC 8554), one level\tsignatures\tpublic\tsignature")
	for _, t := range []lms.Type{lms.LMS_SHA256_M32_H5, lms.LMS_SHA256_M32_H10, lms.LMS_SHA256_M32_H15, lms.LMS_SHA256_M32_H20, lms.LMS_SHA256_M32_H25} {
		h, _ := t.Height()
		for _, o := range []lms.OTSType{lms.LMOTS_SHA256_N32_W1, lms.LMOTS_SHA256_N32_W2, lms.LMOTS_SHA256_N32_W4, lms.LMOTS_SHA256_N32_W8} {
			fmt.Fprintf(tw, "%s/%s\t2^%d\t%d\t%d\n", t, strings.TrimPrefix(o.String(), "LMOTS_SHA256_N32_"), h, lms.PublicKeySize, t.SignatureSize(o))
		}
	}
	return tw.Flush()
}

func (c cli) slhKeygen(args []string) error {
	fs := flag.NewFlagSet("slh keygen", flag.ContinueOnError)
	params := fs.String("params", "SLH-DSA-SHA2-128s", "FIPS 205 parameter set")
	prefix := fs.String("out", "slh", "writes <out>.key and <out>.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := slhdsa.Params(*params)
	pub, priv, err := slhdsa.GenerateKey(p, nil)
	if err != nil {
		return err
	}
	// The parameter set name is the first line, so sign and verify need no flag.
	if err := writeNew(*prefix+".key", append([]byte(*params+"\n"), priv...), 0o600); err != nil {
		return err
	}
	if err := writeNew(*prefix+".pub", append([]byte(*params+"\n"), pub...), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "params      %s\npublic key  %x\n", p, pub)
	return nil
}

func readSLHKey(path string) (slhdsa.Params, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	name, key, ok := strings.Cut(string(b), "\n")
	if !ok {
		return "", nil, fmt.Errorf("%s: missing parameter header", path)
	}
	return slhdsa.Params(name), []byte(key), nil
}

func (c cli) slhSign(args []string) error {
	fs := flag.NewFlagSet("slh sign", flag.ContinueOnError)
	key := fs.String("key", "slh.key", "private key file")
	in := fs.String("in", "-", "message file, - for stdin")
	ctx := fs.String("ctx", "", "context string (at most 255 bytes)")
	det := fs.Bool("deterministic", false, "deterministic instead of hedged signing")
	sigOut := fs.String("sig", "", "signature output file (default: hex to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, priv, err := readSLHKey(*key)
	if err != nil {
		return err
	}
	msg, err := c.readInput(*in)
	if err != nil {
		return err
	}
	sig, err := slhdsa.Sign(p, priv, msg, []byte(*ctx), *det)
	if err != nil {
		return err
	}
	return c.writeSig(*sigOut, sig)
}

func (c cli) slhVerify(args []string) error {
	fs := flag.NewFlagSet("slh verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "slh.pub", "public key file")
	in := fs.String("in", "-", "message file, - for stdin")
	ctx := fs.String("ctx", "", "context string")
	sigPath := fs.String("sig", "", "signature file (raw or hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, pub, err := readSLHKey(*pubPath)
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
	if err := slhdsa.Verify(p, pub, msg, sig, []byte(*ctx)); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "OK")
	return nil
}
