# Wire format design note: introduction v2

**Status**: implemented in commit landing this file.
**Spec**: [specs/001-pq-hybrid-crypto/contracts/introduction-v2.md](../specs/001-pq-hybrid-crypto/contracts/introduction-v2.md)
**Constitution gate**: Quality Gates — "Wire-format changes ... require a `docs/` design note describing the format before code review begins."

## Purpose

`introductionV2` is the post-quantum hybrid replacement for the Alpenhorn `introduction` blob exchanged through the IBE-encrypted mailbox during a friend-request round. It carries everything an initiator publishes about themselves to the (unknown-to-mixers) recipient: per-friend-request KEM ephemerals, long-term identity halves, signature halves, and the BLS PKG-attestation multisig.

The v1 introduction (228 bytes) carries only the X25519 ephemeral pub, the Ed25519 long-term pub, and the Ed25519 signature. Under a "harvest now, decrypt later" adversary, the X25519 ECDH and the Ed25519 signature are both broken once cryptographically relevant quantum hardware exists. The v2 layout pairs each of those with a post-quantum counterpart so the construction survives the loss of either family.

## Wire layout

Fixed-width, big-endian, no length prefixes. Total **6695 bytes**.

| Offset | Length | Field             | Purpose |
|-------:|-------:|-------------------|---------|
|      0 |      1 | `Version` = `0x02`| Schema version. v1 records have a different leading byte (the high byte of `Username`); v2 unmarshaler rejects anything that is not `0x02`. |
|      1 |     64 | `Username`        | The PKG-validated 64-byte identity bytes the initiator targets. (Same role and width as v1.) |
|     65 |     32 | `DHPublicKey`     | Initiator's per-friend-request X25519 ephemeral pub. (Same role as v1.) |
|     97 |   1184 | `MLKEMPublicKey`  | Initiator's per-friend-request ML-KEM-768 ephemeral pub. **NEW.** The responder runs `pqkem.Encapsulate` against this to produce the ML-KEM half of the hybrid shared secret. |
|   1281 |      4 | `DialingRound`    | uint32 BE. The dialing round this friend request binds to. (Same role as v1.) |
|   1285 |     32 | `LongTermKey`     | Initiator's Ed25519 long-term public key. (Same role as v1.) |
|   1317 |   1952 | `LongTermKeyPQ`   | Initiator's ML-DSA-65 long-term public key. **NEW.** Bound to `LongTermKey` by the hybrid identity binding (research.md R4); a verifier cannot independently confirm the binding without the seed but it is enforced operator-side. |
|   3269 |     64 | `Signature`       | Ed25519 signature over the canonical signed message (below). |
|   3333 |   3309 | `SignaturePQ`     | ML-DSA-65 signature over the same canonical signed message. **NEW.** Required: a verifier MUST verify both halves; absence or invalidity of either is rejection. |
|   6642 |     32 | `ServerMultisig`  | BLS multisig over the PKG attestations that this `(Username, LongTermKey)` is the bound identity for the round. (Same role as v1.) |
|   6674 |     21 | `Reserved`        | Zero-padding. Selected so the encoded length is a multiple of 7 (improves IBE chunking alignment). Senders MUST write zeros; receivers MUST NOT depend on the content. |

## Signed message

The bytes covered by `Signature` and `SignaturePQ` are:

```
"NeverlurIntroductionV2"
|| byte(Version)
|| Username[64]
|| DHPublicKey[32]
|| MLKEMPublicKey[1184]
|| big-endian uint32(DialingRound)
|| SHA-512(LongTermKey || LongTermKeyPQ)[64]
```

Including `SHA-512(LongTermKey || LongTermKeyPQ)` in the signed message implements the hybrid identity binding at the introduction layer: an attacker who substitutes either long-term half invalidates both signatures.

## Verification

`introductionV2.Verify(serverKeys []*bls.PublicKey) error` returns `nil` iff **all three** of the following hold:

1. `ed25519.Verify(LongTermKey, msg, Signature)`
2. `pqsig.Verify(LongTermKeyPQ, msg, SignaturePQ)`
3. `bls.VerifyCompressed(serverKeys, attestationMsgs, &ServerMultisig)` (unchanged from v1; verifies the PKG attestations)

Failure of any one is an outright rejection. There is no partial-success state.

## Mailbox-layout impact

`addfriend.MixMessage.EncryptedIntro` is sized at compile time:

```go
SizeIntro          = 6695                    // was 228
SizeEncryptedIntro = SizeIntro + ibe.Overhead
```

This means a mixer or mailbox client built against v2 cannot read mailboxes produced by a v1-only writer (and vice versa). The deployment-wide cut-over is gated by US3's cutover-date mechanism; until US3 lands, a deployment must upgrade all peers within a single dialing round.

## Threat-model impact

The v2 wire format closes the post-quantum gap in the friend-request handshake. Specifically:

- The KEM half (`DHPublicKey` + `MLKEMPublicKey`) feeds the hybrid combiner `hybrid.CombineKEM(ContextKeywheelSeed, ...)`, which produces the keywheel seed. Under harvest-now-decrypt-later, an adversary who later breaks either X25519 or ML-KEM-768 in isolation cannot derive the seed; both halves must be broken simultaneously.
- The signature half (`Signature` + `SignaturePQ`) makes intro forgery require breaking either Ed25519 or ML-DSA-65 alone insufficient; both must fall.
- The identity binding (`LongTermKey` + `LongTermKeyPQ` hashed into `msg`) means an attacker cannot mix-and-match a classical signature from one identity with a PQ signature from another; the SHA-512 over both keys is signed by both keys.

The PKG attestation surface (`ServerMultisig`) is **not** changed by this design note. The PKG attestation is still a BLS multisig over an attestation that binds `(Username, LongTermKey)`. Migrating the PKG attestation to a hybrid construction is a follow-up project and is out of scope for the v2 introduction format.

## Open issues

- **🚧 BLOCKING: ML-KEM is asymmetric; the protocol is symmetric.** Alpenhorn's add-friend protocol exchanges intros *symmetrically* — Alice and Bob each independently emit an intro in the same mixer round, with neither having seen the other's intro. Both sides derive the keywheel seed from `box.Precompute(their_pub, my_priv)`, which is symmetric DH. ML-KEM-768 is fundamentally NOT symmetric: it has an encapsulator role (produces ciphertext + shared secret) and a decapsulator role (consumes ciphertext to recover the shared secret). The ciphertext has to flow back from encapsulator to decapsulator, but the symmetric add-friend round has no place for that traffic. The v2 wire format above carries `MLKEMPublicKey` but no `MLKEMCiphertext`, which means the protocol as drafted cannot actually derive a hybrid shared secret. Resolution options (operator/maintainer decision required before any genIntro/decodeAddFriendMessage code lands):
  - **A. Designate an initiator per friend request** and ship asymmetric intros (initiator carries pub, responder carries CT). Requires the responder to see the initiator's intro before generating their own — incompatible with single-round mixing.
  - **B. Two-round add-friend protocol**: round N exchanges pubs, round N+1 exchanges CTs. Doubles the per-friendship latency. Cleanest from a primitive-correctness standpoint.
  - **C. Stateful cross-round**: both intros carry `MLKEMPublicKey` AND a `MLKEMCiphertext` encapsulated to the *peer's previous-round* pub. Requires client-side state across rounds; the first friendship has no prior round and needs a bootstrap.
  - **D. PQ NIKE primitive**: no NIST-standardized PQ NIKE exists; SIDH/CSIDH families were broken in 2022.
  - **E. Accept the protocol change in B** (two-round) and treat the latency hit as a deliberate tradeoff for harvest-now-decrypt-later resistance.
  This design note (and the spec's data-model.md E10) was written assuming a drop-in wire change. That assumption was wrong. **Until one of the resolution options is picked and reflected in this note, this format MUST NOT be wired into `addfriend.go::genIntro`/`decodeAddFriendMessage`/`newFriend`.**
- **PKG attestation is still classical.** A future revision (call it introduction v3, paired with a PKG-side PQ ceremony) would bind `LongTermKeyPQ` into the attestation as well. Until then, an adversary who breaks BLS could forge the attestation and ride either classical or hybrid intros. The threat model documents this as a known gap; the constitution Principle II requires it be flagged on every PR that touches the PKG attestation surface.
- **Reserved bytes.** The 21 zero-padding bytes are not currently used for anything. A future revision could carry feature flags, extension OIDs, or a compact AEAD tag here. Receivers MUST NOT depend on the content; senders MUST write zeros so receivers can rely on a stable canonical form for the binary diff KAT.
