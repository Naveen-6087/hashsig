package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `usage: hashsig <command> [flags]

commands:
  params                       list supported parameter sets and sizes
  lms keygen|sign|verify|info  stateful LMS/HSS (RFC 8554, SP 800-208)
  slh keygen|sign|verify       stateless SLH-DSA (FIPS 205)

run "hashsig <command> -h" for flags`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "hashsig:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	c := cli{stdin: stdin, out: out}
	switch args[0] {
	case "params":
		return c.params()
	case "lms":
		switch sub {
		case "keygen":
			return c.lmsKeygen(args[2:])
		case "sign":
			return c.lmsSign(args[2:])
		case "verify":
			return c.lmsVerify(args[2:])
		case "info":
			return c.lmsInfo(args[2:])
		}
	case "slh":
		switch sub {
		case "keygen":
			return c.slhKeygen(args[2:])
		case "sign":
			return c.slhSign(args[2:])
		case "verify":
			return c.slhVerify(args[2:])
		}
	case "-h", "--help", "help":
		fmt.Fprintln(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", args, usage)
}

type cli struct {
	stdin io.Reader
	out   io.Writer
}

func (c cli) readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(c.stdin)
	}
	return os.ReadFile(path)
}

func (c cli) writeSig(path string, sig []byte) error {
	if path == "" {
		_, err := fmt.Fprintf(c.out, "%x\n", sig)
		return err
	}
	return os.WriteFile(path, sig, 0o644)
}

// writeNew refuses to overwrite: replacing a key file, or worse resetting its
// state file, would lead to one-time key reuse.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
