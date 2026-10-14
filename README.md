# hashsig

Hash-based post-quantum signatures in Go:

- **LMS / HSS** (RFC 8554, NIST SP 800-208): a from-scratch implementation of the stateful scheme, with crash-safe state handling.
- **SLH-DSA** (FIPS 205): a thin wrapper around [`cloudflare/circl`](https://github.com/cloudflare/circl)'s implementation, giving one API surface and a CLI for both families.

Hash-based schemes rely only on properties of the underlying hash function. That is why they are the conservative choice for post-quantum signatures, and why Ethereum's post-quantum research (Lean Consensus, XMSS-style signatures) builds on them.

## Layout

| Path | Contents |
| --- | --- |
| `lms/` | LM-OTS, LMS trees, HSS verification, the stateful `Signer`, `FileStore` |
| `slhdsa/` | FIPS 205 key generation, hedged/deterministic signing, verification |
| `cmd/hashsig/` | CLI: `params`, `lms keygen/sign/verify/info`, `slh keygen/sign/verify` |
| `testdata/rfc8554.json` | RFC 8554 Appendix F test cases |

## Usage

```bash
go install github.com/Naveen-6087/hashsig/cmd/hashsig@latest
```

```bash
hashsig lms keygen -levels H10/W4,H10/W4 -out validator
```

That writes `validator.key` (seed and identifier, mode 0600), `validator.state` (the next unused leaf at each level, 0600), and `validator.pub`. A two-level H10 key can sign 2^20 messages.

```bash
echo "block 42" | hashsig lms sign -key validator.key -sig block.sig
echo "block 42" | hashsig lms verify -pub validator.pub -sig block.sig
hashsig lms info -key validator.key
```

```bash
hashsig slh keygen -params SLH-DSA-SHA2-128s -out node
echo "hello" | hashsig slh sign -key node.key -ctx app-v1 -sig hello.sig
echo "hello" | hashsig slh verify -pub node.pub -ctx app-v1 -sig hello.sig
```

`hashsig params` lists every parameter set together with its key and signature sizes.

The libraries can be used directly:

```go
levels := []lms.LevelParams{
	{Type: lms.LMS_SHA256_M32_H10, OTSType: lms.LMOTS_SHA256_N32_W4},
	{Type: lms.LMS_SHA256_M32_H10, OTSType: lms.LMOTS_SHA256_N32_W4},
}
signer, err := lms.NewSigner(levels, seed, id, state, lms.FileStore{Path: "key.state"})
sig, err := signer.Sign(msg)
err = lms.VerifyHSS(signer.PublicKey(), msg, sig)
```

## Security assumptions

- **Hash function.** LMS security reduces to second-preimage and related properties of SHA-256 (truncated to n = 32 bytes). SLH-DSA security reduces to the properties of SHA-2 or SHAKE that FIPS 205 lists for the chosen parameter set. No number-theoretic assumption is involved, so Shor's algorithm does not apply. Grover's algorithm only halves the effective security level, and the parameter sets are sized with that in mind.
- **LMS is stateful.** Signing twice with the same one-time key (the same leaf of the same tree) can allow forgeries. The `Signer` handles this as follows:
  - It reserves the next leaf and calls `StateStore.Save` **before** computing the signature. If the save fails, no signature is produced (`TestNoSignatureWithoutDurableState`).
  - `FileStore` writes to a temporary file, fsyncs it, renames it over the state file, and syncs the directory, so a crash leaves either the old state or the new one.
  - A crash after saving but before the signature is delivered burns a leaf. That loses capacity, but it is safe.
  - The CLI refuses to overwrite existing key and state files.

  This protects only against crashes. It does **not** protect against copying the key and state to two machines, or against restoring an old backup of the state. Both lead to key reuse. Treat the state file as part of the key.
- **Child trees and randomizers are derived, not stored.** RFC 8554 leaves child key generation to the implementation. Here, the tree certified by leaf `q` of its parent uses `SEED' = H(SEED || I || q || 0x01)` and `I' = H(SEED || I || q || 0x02)[:16]`. The per-signature randomizer `C` is `H(SEED || I || q || 0x03)`. Both are this project's own choice, not part of the standard. Because of them, re-signing at the same state reproduces byte-identical certifications of child keys, so an upper-level leaf never signs two different messages. The derivation is domain-separated from the RFC 8554 Appendix A private-key derivation, which uses a different input length and a `0xFF` marker.
- **The SLH-DSA cryptography is circl's.** This repository does not reimplement FIPS 205. It checks that the wrapper passes NIST's ACVP vectors and adds nothing on the signing path beyond input validation. Hedged signing (fresh randomness) is the default. Deterministic signing is available because FIPS 205 permits it.
- **No signature aggregation.** Neither LMS nor SLH-DSA supports aggregating signatures, and this repository does not implement any. Post-quantum aggregation proposals for Ethereum, such as aggregating XMSS signatures for Lean Consensus, work by proving many verifications inside a SNARK. That is out of scope here.
- **Side channels.** The LMS code uses Go's `crypto/sha256` and contains no secret-dependent branches beyond those inherent to hash chains. It has not been audited, and no effort was made to protect against fault attacks. Do not use it to protect anything of value.

## Testing

```bash
go test ./...
HASHSIG_FULL_ACVP=1 go test -run TestACVP ./slhdsa
go test ./lms -run '^$' -fuzz FuzzVerifyHSS -fuzztime 60s
```

- **RFC 8554 Appendix F.**
  - Both test cases verify.
  - The second test case (two-level HSS: H10/W4 over H5/W8) is also regenerated from the private seeds it lists. Both public keys and both per-level LMS signatures must match byte for byte.
- **NIST ACVP (FIPS 205).** These are read from the circl module's copy of the ACVP-Server vectors.
  - All 120 keyGen cases.
  - All 168 external/pure sigVer cases, including the expected rejections.
  - sigGen with exact signature matches, for both deterministic and hedged groups (the hedged groups replay the vectors' `additionalRandomness`). The fast `f` sets always run, which is 84 cases. The slow `s` sets are added with `HASHSIG_FULL_ACVP=1`, for 168 cases in total.
- **Properties.**
  - Every LM-OTS type works.
  - Truncation, extension, out-of-range leaves, mismatched types, and byte flips are all rejected.
  - A one-level H5 key (32 signatures) and a two-level H5/H5 key (1,024 signatures) are each exhausted completely, with a check that no one-time key repeats.
  - State is persisted and resumed.
  - Malformed states are rejected.
- **Fuzzing.** `FuzzVerifyHSS` must never panic and must never accept a signature for a message that was not signed.

## Benchmarks

Measured with `go test -bench . -benchmem ./...` using Go 1.26.9 on Windows 11 with 16 logical CPUs. Each LMS row is a single H10 tree with 64-byte messages.

| Operation | W1 | W2 | W4 | W8 |
| --- | --- | --- | --- | --- |
| LMS key generation (H10, 1,024 leaves, parallel) | 37 ms | 23 ms | 27 ms | 137 ms |
| LMS sign (cached tree) | 98 µs | 62 µs | 75 µs | 488 µs |
| LMS verify | 49 µs | 41 µs | 72 µs | 425 µs |
| LMS signature size | 8,844 B | 4,620 B | 2,508 B | 1,452 B |

| Operation | Time |
| --- | --- |
| HSS H10/W4 + H10/W4 sign (amortized over bottom-tree rebuilds) | 215 µs |
| HSS H10/W4 + H10/W4 verify | 126 µs |
| SLH-DSA-SHA2-128s sign / verify | 332 ms / 0.42 ms |
| SLH-DSA-SHA2-128f sign / verify | 16 ms / 1.0 ms |
| SLH-DSA-SHAKE-128f sign / verify | 56 ms / 3.4 ms |

The trade-off is visible in the numbers. LMS signatures are small and fast, but every key has a fixed signature budget and needs careful state handling. SLH-DSA has no state, but SLH-DSA-SHA2-128s signatures are 7,856 bytes and take hundreds of milliseconds to produce.

## Limitations

- Only the RFC 8554 parameter sets (SHA-256, n = m = 32) are implemented. The SHA-256/192 and SHAKE256 variants added by SP 800-208 are not.
- Key generation recomputes whole trees. A tree is rebuilt whenever the signer moves to a new lower-level tree, and when a key is loaded. A single-level H20 tree therefore takes around 30 seconds to load on the machine above (1,024 times the H10 time). Use HSS levels of H10 or H15 instead.
- There is no XMSS / XMSS^MT, and no hardware-backed state counter.
