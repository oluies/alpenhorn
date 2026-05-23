# Contract: ML-KEM-768 KAT integration

**Package**: `github.com/oluies/neverlur/pqkem`
**Standards reference**: FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard), final August 2024.

## Required tests

`pqkem/kat_test.go` MUST exercise:

1. **Deterministic keygen KAT** — Given a 32-byte `d` and 32-byte `z` seed pair from the FIPS 203 known-answer test vectors, `pqkem.GenerateKey(d, z)` MUST produce the documented `(ek, dk)` byte strings.
2. **Deterministic encapsulation KAT** — Given a public key `ek` and 32-byte coins `m` from the FIPS 203 vectors, `pqkem.EncapsulateDeterministic(ek, m)` MUST produce the documented `(c, K)`.
3. **Decapsulation KAT** — Given a decapsulation key `dk` and ciphertext `c` from the FIPS 203 vectors, `pqkem.Decapsulate(dk, c)` MUST produce the documented `K`.
4. **Implicit-rejection KAT** — A malformed ciphertext MUST cause `Decapsulate` to return the implicit-rejection key documented in the vector (not an error). The contract delegates this to CIRCL's `mlkem768.PrivateKey.Decapsulate`, but the test verifies the wrapper preserves the behavior.

## Test-vector source

Vectors are taken from the NIST ACVP-Server reference output for ML-KEM-768 and re-committed under `pqkem/testdata/fips203-vectors.json`. The commit message MUST cite the upstream artifact URL and SHA-256 of the vector file used. (Constitution Quality Gate: "review must explicitly confirm KATs were checked against an authoritative source.")

## Wrapper contract

```go
// GenerateKey returns a fresh ML-KEM-768 keypair using crypto/rand.
func GenerateKey() (*mlkem768.PublicKey, *mlkem768.PrivateKey, error)

// Encapsulate returns a ciphertext and shared secret for the given public key.
func Encapsulate(pub *mlkem768.PublicKey) (ct []byte, ss []byte, err error)

// Decapsulate returns the shared secret for the given ciphertext.
// On implicit-rejection it returns a pseudorandom but deterministic 32-byte value.
func Decapsulate(priv *mlkem768.PrivateKey, ct []byte) (ss []byte, err error)
```

`ss` is always exactly 32 bytes. `ct` is always exactly 1088 bytes.
