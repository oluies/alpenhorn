# Contract: hybrid.CombineKEM and hybrid.SignedMessage

**Package**: `github.com/oluies/neverlur/hybrid`
**Stability**: stable from this feature onward; changes require a wire-format design note.

## Constants

```go
// Domain-separation labels for the KEM combiner.
const (
    ContextFriendRequest = "friend-request"
    ContextKeywheelSeed  = "keywheel-seed"
    ContextEdTLSSession  = "edtls-session"
)

// Domain-separation prefix for the signed-message helper.
const SigMessagePrefix = "neverlur-hybrid-sig-v1"
```

## Functions

```go
// CombineKEM derives a 32-byte session secret from a classical X25519 shared
// secret and an ML-KEM-768 shared secret, binding both to the provided
// transcript and to a domain-separation context label.
//
// Both ssX25519 and ssMLKEM MUST be exactly 32 bytes.
// transcript carries the full hybrid handshake context — see
// research.md R3 for the construction. Callers MUST NOT reuse a
// transcript across distinct handshakes.
//
// The result is suitable as the seed input to keywheel.Wheel.Put.
func CombineKEM(context string, transcript []byte, ssX25519, ssMLKEM []byte) (*[32]byte, error)

// SignedMessage produces the byte string that hybrid signers and verifiers
// agree on for a given artifact. It embeds SigMessagePrefix, the artifact
// payload, and the SHA-512 hash of both long-term public keys. This binds
// signatures to the specific (Ed25519, ML-DSA-65) identity pair.
func SignedMessage(payload []byte, edPub []byte, pqPub []byte) []byte
```

## Errors

- `ErrInvalidShareLength`: returned by `CombineKEM` if either shared-secret input is not 32 bytes.
- `ErrEmptyTranscript`: returned by `CombineKEM` if `transcript` is nil or zero-length.

## Test obligations

- KAT-style fixed-input test asserting `CombineKEM` produces a stable, documented output for one chosen `(context, transcript, ssX25519, ssMLKEM)` tuple. The fixture is committed in `hybrid/testdata/combine-kat.json`.
- Half-compromise test asserting an adversary with only `ssX25519` or only `ssMLKEM` cannot reproduce the combined output (SC-003, SC-004).
- Context-separation test asserting `CombineKEM(ContextFriendRequest, …) != CombineKEM(ContextKeywheelSeed, …)` for identical other inputs.
