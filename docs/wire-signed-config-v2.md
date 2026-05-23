# Wire format design note: SignedConfig v2

**Status**: implemented in commit landing this file.
**Spec**: [specs/001-pq-hybrid-crypto/contracts/signed-config-v2.md](../specs/001-pq-hybrid-crypto/contracts/signed-config-v2.md)
**Constitution gate**: Quality Gates — wire-format design note required before code review begins.

## Purpose

`SignedConfig` is the hash-chained, multi-guardian-signed configuration record for the AddFriend, Dialing, and Convo services. Every config in the chain names the guardians authorized to sign the next config; trust in the system rolls forward through this hash-chain. If a quantum adversary can forge guardian signatures, they can fork the chain and redirect every client to a malicious mixer set. So this surface is part of the same atomic safety unit as the introduction format: both must move to hybrid at the same time.

The v1 schema (in `config/config.go`) has `Guardian.Key ed25519.PublicKey` and `Signatures map[string][]byte` where each value is an Ed25519 signature. v2 swaps each of those to its hybrid counterpart.

## v2 Go schema

```go
const SignedConfigVersion = 2

type SignedConfig struct {
    Version          int                              // = 2 (was 1)
    Service          string                           // unchanged
    Created          time.Time                        // unchanged
    Expires          time.Time                        // unchanged
    PrevConfigHash   string                           // SHA-512 hex of the prior v2 record (unchanged role; v1 records are not in the chain)
    Inner            InnerConfig                      // unchanged
    Guardians        []Guardian                       // see below
    Signatures       map[string]HybridSignature       // was map[string][]byte
    MinClientVersion int                              // NEW: minimum peer schema version that may consume this config
}

type Guardian struct {
    Username string
    Key      ed25519.PublicKey   // unchanged role; the classical half
    PQKey    pqsig.PublicKey     // NEW: ML-DSA-65 half, R4-bound to Key
}

type HybridSignature struct {
    Ed [64]byte    // Ed25519
    PQ [3309]byte  // ML-DSA-65
}
// Wire encoding: base64( Ed || PQ ) — fixed-width concat, 3373 raw bytes, ~4500 base64 chars.
```

## Verifier contract

`SignedConfig.Verify()` returns `nil` iff for **every** guardian listed in `Guardians`, the corresponding `Signatures[base32(Key)]` `HybridSignature`:

1. has `ed25519.Verify(Guardian.Key, msg, Sig.Ed[:]) == true`, AND
2. has `pqsig.Verify(&Guardian.PQKey, msg, Sig.PQ[:]) == true`.

`VerifyConfigChain(configs...)` additionally requires:

- Each adjacent (prev, curr) pair links via `curr.PrevConfigHash == prev.Hash()`.
- Every guardian listed in `prev.Guardians` AND every new guardian introduced in `curr.Guardians` must have a verifying `HybridSignature` on `curr`.

Failure of any check is rejection. There is no partial-success state.

## JSON wire encoding

The on-wire form is JSON (via `easyjson`). The relevant changes vs. v1:

```json
{
  "Version": 2,
  "Service": "AddFriend",
  ...
  "Guardians": [
    {
      "Username": "alice",
      "Key": "AAECAwQ...==",          // ed25519 pub, base64
      "PQKey": "AAECAwQ...=="          // ml-dsa-65 pub, base64
    }
  ],
  "Signatures": {
    "<base32(Key)>": "<base64( Ed || PQ )>"
  },
  "MinClientVersion": 2,
  ...
}
```

A consumer that does not know about `PQKey` or about the new `Signatures` value type will fail to parse the record. This is intentional: v1 consumers MUST NOT silently fall through on a v2 record (per Constitution Principle V, no silent downgrade).

## Mixed-version handling

This commit does **not** add a transition path for accepting v1 records during a deployment-wide transition window. That is US3's responsibility (the cutover-date mechanism plus the structured `event=pq.downgrade` / `event=pq.reject` logs). Until US3 lands:

- A deployment running this code base produces ONLY v2 records.
- A deployment receiving a v1 record on a v2 codebase parses it as malformed and rejects it.
- Operators must coordinate the upgrade across guardians, coordinator, mixers, PKG, CDN, and clients within a single configuration-chain transition.

## Threat-model impact

Once this lands, every signed configuration carries:

- A classical Ed25519 signature, verifiable by anyone with the guardian's Ed25519 key.
- A post-quantum ML-DSA-65 signature, verifiable by anyone with the guardian's ML-DSA-65 key.
- A binding between the two via the R4 derivation `pqsig.DeriveFromEd25519Seed(guardian.Ed25519Seed) -> PQKey`. The verifier cannot independently re-derive (it does not have the seed) but the binding is checked operator-side at guardian-key-generation time, and is documented on the `Guardian` struct.

An adversary who later breaks Ed25519 alone cannot forge a new config: they would also need to break ML-DSA-65 against the same guardian. Symmetrically for breaking ML-DSA-65 alone. The hybrid construction inherits the security of the stronger half.

The chain-of-trust property (each config signed by the previous config's guardians) is preserved. The same guardians who could fork the chain in v1 can fork the chain in v2 — what changes is the hardness of forging a guardian signature, not the trust topology.

## Open issues

- **Guardian key rotation** still hangs on its own follow-up (US4). The current verifier requires every listed guardian in BOTH the prior and current config to sign the current config; that does not support a clean "swap one guardian for another" operation. US4 will address this with `PrevIdentityHash`-based rotation events.
- **Signature size**. A 5-guardian config grows the signature material from 5 × 64 = 320 bytes to 5 × 3373 = 16 865 bytes. For configs distributed via CDN this is negligible. For inline-signature paths (none in v2 currently) it would be a concern.
- **JSON base64 vs. raw**. We choose base64 for compactness within JSON; an alternative would be hex (twice the bytes) or a binary side-channel (out of scope for the existing `SignedConfig` plumbing).
