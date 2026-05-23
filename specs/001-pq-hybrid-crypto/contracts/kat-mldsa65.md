# Contract: ML-DSA-65 KAT integration

**Package**: `github.com/oluies/neverlur/pqsig`
**Standards reference**: FIPS 204 (Module-Lattice-Based Digital Signature Standard), final August 2024.

## Required tests

`pqsig/kat_test.go` MUST exercise:

1. **Deterministic keygen KAT** — Given a 32-byte seed `ξ` from the FIPS 204 known-answer test vectors, `pqsig.GenerateKeyFromSeed(ξ)` MUST produce the documented `(pk, sk)` byte strings.
2. **Deterministic signing KAT** — Given a private key `sk`, a message `M`, and (per the deterministic-signing variant) RNG bytes set to zero, `pqsig.SignDeterministic(sk, M)` MUST produce the documented signature `σ`.
3. **Verification KAT** — Given a public key `pk`, message `M`, and signature `σ` from the FIPS 204 vectors (both positive and negative cases), `pqsig.Verify(pk, M, σ)` MUST return the documented result.

## Test-vector source

Vectors from the NIST ACVP-Server ML-DSA-65 reference output, committed under `pqsig/testdata/fips204-vectors.json` with upstream URL and SHA-256 cited in the commit message.

## Wrapper contract

```go
// GenerateKey returns a fresh ML-DSA-65 keypair from crypto/rand.
func GenerateKey() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error)

// GenerateKeyFromSeed returns a deterministic ML-DSA-65 keypair from a 32-byte seed.
// This is the constructor used to derive a PQ identity from an Ed25519 seed (R4).
func GenerateKeyFromSeed(seed []byte) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error)

// Sign produces a randomized ML-DSA-65 signature over msg.
func Sign(priv *mldsa65.PrivateKey, msg []byte) ([]byte, error)

// Verify returns true iff sig is a valid ML-DSA-65 signature over msg under pub.
// The function MUST be constant-time with respect to sig material — failure
// timing MUST NOT leak information about which intermediate check failed.
func Verify(pub *mldsa65.PublicKey, msg, sig []byte) bool
```

`Sign` always returns exactly 3309 bytes. Public keys are 1952 bytes; private keys are 4032 bytes.

## Hybrid identity derivation contract

```go
// DeriveFromEd25519Seed implements R4: it returns the ML-DSA-65 keypair bound
// to the given Ed25519 seed via HKDF-SHA512.
func DeriveFromEd25519Seed(edSeed []byte) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error)
```

A test `TestDeriveBindingStable` asserts the output is byte-stable across calls and across CIRCL minor versions; the bound output for a fixed `edSeed` is committed in `pqsig/testdata/binding-kat.json`.
