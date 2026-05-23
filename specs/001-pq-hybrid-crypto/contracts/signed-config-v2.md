# Contract: SignedConfig v2 wire format

**Package**: `github.com/oluies/neverlur/config`
**Schema version**: 2 (was 1)
**Design note**: `docs/wire-signed-config-v2.md` (mandated by constitution Quality Gate)

## Go types

```go
const SignedConfigVersion = 2

type SignedConfig struct {
    Version          int
    Service          string
    Created          time.Time
    Expires          time.Time
    PrevConfigHash   string                          // SHA-512 hex of prior v2 record
    Inner            InnerConfig
    Guardians        []Guardian
    Signatures       map[string]hybrid.HybridSignature
    MinClientVersion int                             // NEW: minimum peer version that may consume this config
}

type Guardian struct {
    Username string
    Key      ed25519.PublicKey       // classical pub (was the only field in v1)
    PQKey    mldsa65.PublicKey       // NEW
}
```

## JSON encoding

- All new fields use lowerCamelCase JSON tags consistent with the existing schema.
- `Signatures` map values encode as base64-of-`(Ed || PQ)` for compactness; the decoder asserts the byte count is exactly 3373.
- `MinClientVersion` is required (omitting it on a v2 record is an error).

## Verifier contract

```go
// Verify returns nil iff every required hybrid signature on this config
// verifies under the appropriate guardian's hybrid identity, AND the
// caller's protocol version is at least MinClientVersion.
func (c *SignedConfig) Verify() error

// VerifyConfigChain returns nil iff the chain links via PrevConfigHash AND
// every transition from config N to config N+1 is signed by the union of
// (guardians of N) and (guardians of N+1 introduced in N+1), each with a
// valid HybridSignature.
func VerifyConfigChain(configs ...*SignedConfig) error
```

Behavior of `Verify` against a v1 record:
- Before the cutover instant: parse via the v1 codec, verify Ed25519 only, return nil with an in-band `event=pq.downgrade` log.
- After the cutover instant: return `ErrClassicalOnlyAfterCutover`.

## Tests

`config/config_test.go` MUST include:
- `TestVerifyV2Roundtrip` — generate hybrid identities, build a v2 config, sign with both halves, verify.
- `TestRejectStrippedPQSignature` — take a valid v2 config, replace `Signatures[g].PQ` with zeros, assert `Verify` returns a `HybridVerifyError` naming the PQ half.
- `TestRejectStrippedEdSignature` — symmetric.
- `TestRejectMixedV1V2Chain` — assemble a chain where one config is v1 and one is v2, assert `VerifyConfigChain` rejects (constitution Compatibility section: "mixed-version config chains within a single dialing round are forbidden").
- `TestCutoverAcceptsV1Before` — set `NEVERLUR_PQ_CUTOVER` one hour in the future, present a v1 config, assert it verifies (with downgrade log).
- `TestCutoverRejectsV1After` — set `NEVERLUR_PQ_CUTOVER` one hour in the past, present a v1 config, assert `ErrClassicalOnlyAfterCutover`.
