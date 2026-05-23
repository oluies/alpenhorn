# Wire format design note: introduction v2 (option F — static-ephemeral hybrid)

**Status**: design corrected after prior 1-round-symmetric assumption was found unworkable for ML-KEM (see "Design history" below). Wire layout below is the authoritative one.
**Spec**: [specs/001-pq-hybrid-crypto/contracts/introduction-v2.md](../specs/001-pq-hybrid-crypto/contracts/introduction-v2.md) (will be revised to match this note)
**Constitution gate**: Quality Gates — "Wire-format changes ... require a `docs/` design note describing the format before code review begins."

## Purpose

`introductionV2` is the post-quantum hybrid replacement for the Alpenhorn `introduction` blob exchanged through the IBE-encrypted mailbox during a friend-request round. It carries everything an initiator publishes about themselves to the (unknown-to-mixers) recipient: the X25519 ephemeral, an ML-KEM-768 ciphertext encapsulated to the recipient's long-term ML-KEM public key, the sender's long-term identity halves, the hybrid signature halves, and the BLS PKG-attestation multisig.

The v1 introduction (228 bytes) carries only an X25519 ephemeral pub, the Ed25519 long-term pub, and an Ed25519 signature. Under a "harvest now, decrypt later" adversary, the X25519 ECDH and the Ed25519 signature both fall once a cryptographically relevant quantum computer exists. The v2 layout below pairs each of those with a post-quantum counterpart so the construction survives the loss of either family.

## Design choice: static-ephemeral hybrid (option F)

ML-KEM is fundamentally asymmetric — it has an encapsulator role (produces ciphertext + shared secret) and a decapsulator role (consumes ciphertext to recover the shared secret). Alpenhorn's add-friend protocol is symmetric — Alice and Bob each independently emit an intro in the same mixer round, with neither having seen the other's intro. The two structures don't compose without help.

This design picks **static-ephemeral** as the resolution: every user has a **long-term ML-KEM-768 keypair** (published via the PKG alongside their Ed25519 and ML-DSA-65 long-term keys). The per-friend-request ephemeral is X25519 only. Per intro:

- The sender uses the recipient's long-term ML-KEM public key (looked up from the PKG / from a prior friendship) to encapsulate, producing a ciphertext and a shared secret.
- The sender emits the ciphertext in its intro.
- The recipient decapsulates the ciphertext with its own long-term ML-KEM private key to recover the same shared secret.

Each side knows **two** ML-KEM shared secrets per friendship:

- `ssOutgoing` — what they themselves computed by encapsulating to the peer's long-term ML-KEM pub.
- `ssIncoming` — what they recovered by decapsulating the peer's ciphertext.

The keywheel seed is derived from `HKDF(ssX25519 || canonicalOrder(ssOutgoing, ssIncoming))` so both sides agree byte-for-byte.

### Forward-secrecy caveat

The X25519 half retains full forward secrecy via the per-friend-request ephemeral. The ML-KEM half does **not**: the long-term ML-KEM-768 private key, if it ever leaks (compromise or quantum break of that specific key), retroactively decapsulates every ciphertext that was encapsulated to it.

The hybrid combiner means an adversary needs to break BOTH families to recover the keywheel seed. So the security guarantee remains "confidentiality holds if either family is unbroken." What's lost is the stronger guarantee "confidentiality holds against future compromise of any one long-term key." The threat model in the constitution (Principle III) does not require the stronger property; harvest-now-decrypt-later resistance is intact as long as ML-KEM long-term keys are kept private with the same care as the Ed25519 and ML-DSA-65 long-term keys.

This is the same tradeoff BoringSSL/AWS-LC accept in their static-key hybrids. It is recorded here so reviewers see it.

## Wire layout

Fixed-width, big-endian, no length prefixes. Total **6580 bytes**.

| Offset | Length | Field             | Purpose |
|-------:|-------:|-------------------|---------|
|      0 |      1 | `Version` = `0x02`| Schema version. v1 records have a different leading byte (the high byte of `Username`); v2 unmarshaler rejects anything that is not `0x02`. |
|      1 |     64 | `Username`        | The PKG-validated 64-byte identity bytes the initiator targets. (Same role and width as v1.) |
|     65 |     32 | `DHPublicKey`     | Initiator's per-friend-request X25519 ephemeral pub. (Same role as v1.) |
|     97 |   1088 | `MLKEMCiphertext` | ML-KEM-768 ciphertext encapsulated to the **recipient's** long-term ML-KEM-768 public key. **NEW.** Recipient runs `pqkem.Decapsulate(recipient_LT_MLKEM_priv, MLKEMCiphertext)` to recover the sender's chosen shared secret. |
|   1185 |      4 | `DialingRound`    | uint32 BE. The dialing round this friend request binds to. (Same role as v1.) |
|   1189 |     32 | `LongTermKey`     | Initiator's Ed25519 long-term public key. (Same role as v1.) |
|   1221 |   1952 | `LongTermKeyPQ`   | Initiator's ML-DSA-65 long-term public key. **NEW.** Bound to `LongTermKey` by the hybrid identity binding (research.md R4). |
|   3173 |     64 | `Signature`       | Ed25519 signature over the canonical signed message (below). |
|   3237 |   3309 | `SignaturePQ`     | ML-DSA-65 signature over the same canonical signed message. **NEW.** Required: a verifier MUST verify both halves; absence or invalidity of either is rejection. |
|   6546 |     32 | `ServerMultisig`  | BLS multisig over the PKG attestations that this `(Username, LongTermKey, LongTermKeyPQ, LongTermMLKEMPub)` is the bound identity for the round. (Role is unchanged; the attestation **payload** is extended — see PKG attestation section.) |
|   6578 |      2 | `Reserved`        | Zero-padding so the encoded length is a multiple of 7 (improves IBE chunking alignment). Senders MUST write zeros; receivers MUST NOT depend on the content. |

`LongTermMLKEMPub` is **NOT** carried in the intro. The recipient looked it up from the PKG when they registered, so the recipient knows their own LT ML-KEM pub. The sender looked the *recipient's* LT ML-KEM pub up via the PKG / from a prior friendship before constructing the intro. Keeping the LT ML-KEM pub out of the intro saves 1184 bytes per intro and avoids redundancy with the PKG.

## Signed message

The bytes covered by `Signature` and `SignaturePQ` are:

```
"NeverlurIntroductionV2"
|| byte(Version)
|| Username[64]
|| DHPublicKey[32]
|| MLKEMCiphertext[1088]
|| big-endian uint32(DialingRound)
|| SHA-512(LongTermKey || LongTermKeyPQ)[64]
```

Including `SHA-512(LongTermKey || LongTermKeyPQ)` in the signed message implements the hybrid identity binding at the introduction layer: an attacker who substitutes either long-term half invalidates both signatures.

## Verification

`introductionV2.Verify(serverKeys []*bls.PublicKey) error` returns `nil` iff **all three** of the following hold:

1. `ed25519.Verify(LongTermKey, msg, Signature)`
2. `pqsig.Verify(LongTermKeyPQ, msg, SignaturePQ)`
3. `bls.VerifyCompressed(serverKeys, attestationMsgs, &ServerMultisig)` — the attestation payload includes `LongTermMLKEMPub` (see PKG section); the verifier looks it up from the PKG-published identity record for `Username` and binds it into the attestation message.

Failure of any one is an outright rejection. There is no partial-success state.

## Keywheel seed derivation

Once both intros (Alice's and Bob's) are in hand, each side derives the same keywheel seed:

```
ssX25519       = curve25519.X25519(myX25519Priv, peerX25519Pub)
ssOutgoing     = pqkem.Encapsulate(peerLongTermMLKEMPub) // computed locally; sent as MLKEMCiphertext
ssIncoming     = pqkem.Decapsulate(myLongTermMLKEMPriv, peerMLKEMCiphertext)

// canonical ordering so both sides feed the combiner the same bytes:
ssAliceEncap = (the side whose username sorts first encapsulated this)
ssBobEncap   = (the other side encapsulated this)

transcript     = "neverlur-keywheel-seed-v2"
              || canonicalAlpha(aliceLTMLKEMPub, bobLTMLKEMPub)
              || canonicalAlpha(aliceMLKEMCT, bobMLKEMCT)
              || canonicalAlpha(aliceX25519Pub, bobX25519Pub)
              || big-endian uint32(dialingRound)

combinerInput  = ssX25519 || ssAliceEncap || ssBobEncap
seed           = hybrid.CombineKEM(ContextKeywheelSeed, transcript, ssX25519, ssAliceEncap||ssBobEncap)
```

`hybrid.CombineKEM` is extended (or a `CombineKEMTwoPQ` sibling is added) to accept two PQ shared secrets. Each is 32 bytes; the combiner concatenates them in the canonical Alpha order before mixing.

## PKG attestation extension (DEPENDENT WORK, NOT in this commit)

Option F requires the PKG to publish each user's long-term ML-KEM-768 public key and to attest it alongside the Ed25519 and ML-DSA-65 keys. The existing attestation is:

```go
type Attestation struct {
    AttestKey       *bls.PublicKey
    UserIdentity    *[64]byte
    UserLongTermKey ed25519.PublicKey
}
```

The v2 attestation needs to extend to:

```go
type Attestation struct {
    AttestKey            *bls.PublicKey
    UserIdentity         *[64]byte
    UserLongTermKey      ed25519.PublicKey
    UserLongTermKeyPQ    []byte // ML-DSA-65 packed pub
    UserLongTermMLKEMPub []byte // ML-KEM-768 packed pub
}
```

with the marshal/verify paths extended in lockstep. This is a PKG-side change of moderate scope. It is **not** part of this commit; this commit only updates the wire format and the foundational identity types.

## Mailbox-layout impact

`addfriend.MixMessage.EncryptedIntro` is sized at compile time. With option F's wire layout:

```go
SizeIntroV2          = 6580                       // was 228 in v1
SizeEncryptedIntroV2 = SizeIntroV2 + ibe.Overhead
```

A mixer or mailbox client built against v2 cannot read mailboxes produced by a v1-only writer (and vice versa). The deployment-wide cutover is gated by US3's cutover-date mechanism; until US3 lands, a deployment must upgrade all peers within a single dialing round.

## Threat-model impact

The v2 wire format closes the post-quantum gap in the friend-request handshake. Specifically:

- The KEM half (`DHPublicKey` + `MLKEMCiphertext`) feeds the hybrid combiner. Under harvest-now-decrypt-later, an adversary who later breaks **either** X25519 **or** ML-KEM-768 in isolation cannot derive the seed; both halves must be broken simultaneously **and** (for the PQ half) the adversary must additionally compromise both peers' long-term ML-KEM private keys.
- The signature half (`Signature` + `SignaturePQ`) makes intro forgery require breaking either Ed25519 or ML-DSA-65 alone insufficient; both must fall.
- The identity binding (`LongTermKey` + `LongTermKeyPQ` hashed into `msg`) means an attacker cannot mix-and-match a classical signature from one identity with a PQ signature from another; the SHA-512 over both keys is signed by both keys.

The PKG attestation surface needs to be extended (see PKG section above). Until that lands, an attacker who breaks BLS could forge an attestation that binds a `LongTermMLKEMPub` controlled by the attacker, which would let them later decapsulate that user's intros. The PKG-attestation hybrid migration is the next major sub-project after the addfriend wire switch.

## Design history

The initial design assumed a symmetric 1-round ephemeral-ephemeral hybrid: both intros carry `MLKEMPublicKey` for the sender's per-friend-request ephemeral ML-KEM keypair. This was found unworkable during implementation because ML-KEM has no NIKE form — given two ephemeral ML-KEM public keys exchanged in parallel, neither side can derive a shared secret without an encap/decap step that the symmetric 1-round protocol has nowhere to host.

The candidate resolutions were enumerated:

- **B**: two-round add-friend protocol (round N pubs, round N+1 CTs). Full ephemeral-ephemeral FS. Doubles latency.
- **C**: stateful cross-round (CT encap'd to peer's previous-round pub). Mixed-purity semantics for first friendship.
- **D**: NIKE-style hybrid PQ primitive. None NIST-standardized.
- **E**: accept B's latency hit.
- **F (this design)**: static-ephemeral. Long-term ML-KEM-768 keypair per user. 1-round. PQ-half FS depends on long-term ML-KEM key staying private.

F was picked for its combination of single-round latency, deployability, and acceptable security tradeoff. The losing alternatives are recorded here so future revisions can revisit the choice.

## Open issues

- **PKG attestation extension** is a prerequisite for this design and is its own scope of work (see PKG attestation section above).
- **Reserved bytes.** The 2 zero-padding bytes are not currently used. A future revision could carry a feature flag here. Receivers MUST NOT depend on the content; senders MUST write zeros.
- **`hybrid.CombineKEM` signature change.** The combiner currently accepts a single PQ shared secret; option F needs two. The extension can be done either by accepting `ssMLKEM = ssOutgoing || ssIncoming` (caller-side concatenation, combiner stays 1-arg) or by introducing `CombineKEMTwoPQ` (combiner-side change). The caller-side concatenation preserves the existing combiner contract and keeps the half-compromise tests valid as-is.
