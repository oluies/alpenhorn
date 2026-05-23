# Contract: introduction v2 wire format

**Package**: `github.com/oluies/neverlur` (top-level, `intro.go`)
**Schema version**: 2 (was 1)
**Design note**: `docs/wire-introduction-v2.md`

## On-wire layout

Big-endian fixed-width. Total **6695 bytes** (offset table reproduced from `data-model.md` E7):

| Offset | Length | Field           |
|-------:|-------:|-----------------|
|      0 |      1 | `Version` = 2   |
|      1 |     64 | `Username`      |
|     65 |     32 | `DHPublicKey`   |
|     97 |   1184 | `MLKEMPublicKey`|
|   1281 |      4 | `DialingRound`  |
|   1285 |     32 | `LongTermKey`   |
|   1317 |   1952 | `LongTermKeyPQ` |
|   3269 |     64 | `Signature`     |
|   3333 |   3309 | `SignaturePQ`   |
|   6642 |     32 | `ServerMultisig`|
|   6674 |     21 | reserved (zero) |

## Go type

```go
type introductionV2 struct {
    Version          byte
    Username         [64]byte
    DHPublicKey      [32]byte
    MLKEMPublicKey   [1184]byte
    DialingRound     uint32
    LongTermKey      [32]byte
    LongTermKeyPQ    [1952]byte
    Signature        [64]byte
    SignaturePQ      [3309]byte
    ServerMultisig   [32]byte
    _                [21]byte // reserved
}

const SizeIntro = 6695  // up from 228 (v1)
```

## Signed message (`msg`)

```
"NeverlurIntroductionV2"
|| byte(Version)
|| Username[64]
|| DHPublicKey[32]
|| MLKEMPublicKey[1184]
|| big-endian uint32(DialingRound)
|| SHA-512(LongTermKey || LongTermKeyPQ)[64]
```

## Sign / Verify contract

```go
func (i *introductionV2) Sign(id *HybridIdentity) error
func (i *introductionV2) Verify(serverKeys []*bls.PublicKey) error
```

`Verify` returns nil iff:
1. `ed25519.Verify(i.LongTermKey, msg, i.Signature)`
2. `mldsa65.Verify(i.LongTermKeyPQ, msg, i.SignaturePQ)`
3. `bls.VerifyCompressed(serverKeys, msgs, &i.ServerMultisig)` (unchanged role)

All three MUST succeed.

## Marshaler contract

- `MarshalBinary` writes exactly `SizeIntro` bytes.
- `UnmarshalBinary` MUST reject any input whose first byte is not `0x02` (the v1 fallback path is provided only via a separate `UnmarshalBinaryV1Fallback` helper used only in pre-cutover compatibility code).

## Tests

`intro_test.go`:
- `TestSignVerifyRoundtrip`
- `TestVerifyRejectsForgedClassicalSig`
- `TestVerifyRejectsForgedPQSig`
- `TestVerifyRejectsSubstitutedPQKey` — keeps a valid Ed25519 signature, replaces `LongTermKeyPQ` with a different valid ML-DSA-65 key, asserts rejection (the SHA-512 hash binding inside `msg` causes the Ed25519 signature to fail too — but the test asserts the *PQ* check independently rejects the PQ-substituted form regardless).
- `TestUnmarshalRejectsWrongVersion` — input with first byte `0x01` and v2-length is rejected.
