# Wire format design note: PKG attestation v2

**Status**: design note. Implementation is the next sub-project after [SignedConfig v2](wire-signed-config-v2.md) lands.
**Spec**: extends [specs/001-pq-hybrid-crypto/spec.md](../specs/001-pq-hybrid-crypto/spec.md) (will be added as a contracts/ entry when implementation begins)
**Constitution gate**: Quality Gates — "Wire-format changes ... require a `docs/` design note describing the format before code review begins."

## Why this exists

The static-ephemeral hybrid friend-request design ([wire-introduction-v2.md option F](wire-introduction-v2.md#design-choice-static-ephemeral-hybrid-option-f)) requires every Neverlur user to publish a **long-term ML-KEM-768 public key** in addition to the existing Ed25519 and ML-DSA-65 long-term keys. The encapsulator side of every friend-request handshake looks the recipient's long-term ML-KEM-768 pub up via the PKG before encapsulating to it.

If the PKG only attests the Ed25519 pub (current v1 behavior), an adversary who breaks BLS can forge an attestation that binds an attacker-controlled long-term ML-KEM-768 pub to a victim's username. Future friend requests sent to that victim would encapsulate to the attacker's key, letting the attacker decapsulate the PQ half of the keywheel seed (the X25519 half retains its forward secrecy, so the combiner still provides confidentiality — but the security margin is reduced).

The PKG attestation v2 extension closes this gap by binding the ML-KEM-768 pub (and the ML-DSA-65 pub) into the BLS-multisigned attestation.

## v1 attestation (current)

`pkg.Attestation` in the inherited Alpenhorn code is:

```go
type Attestation struct {
    AttestKey       *bls.PublicKey   // the PKG server's BLS signing key
    UserIdentity    *[64]byte        // PKG-validated 64-byte username identity
    UserLongTermKey ed25519.PublicKey
}
```

`Attestation.Marshal()` produces the canonical byte string covered by the BLS signature. The PKG servers each sign it; clients verify the BLS multisig over each PKG's `AttestKey`.

## v2 attestation (proposed)

```go
type Attestation struct {
    AttestKey            *bls.PublicKey
    UserIdentity         *[64]byte
    UserLongTermKey      ed25519.PublicKey
    UserLongTermKeyPQ    []byte           // pqsig.PackPublicKey(...) — 1952 bytes
    UserLongTermMLKEMPub []byte           // pqkem.PackPublicKey(...) — 1184 bytes
}
```

The marshal format adds the two new fields after the existing ones, length-prefixed (BE uint16 length each, to support future field additions without re-breaking the wire). v1 receivers see truncated bytes and reject; v2 receivers parse both halves and verify the full binding.

## Verifier contract

Each PKG server's per-user attestation MUST attest the **R4-derived** PQ keys, not arbitrary keys. The PKG re-runs the R4 derivation (`pqsig.DeriveFromEd25519Seed` and `pqkem.DeriveFromEd25519Seed`) on each user's Ed25519 seed at registration time and refuses to attest mismatched values. This makes the binding cryptographic, not merely procedural: an attacker who substitutes a non-R4-derived ML-KEM pub fails the PKG's own validation before the attestation is even produced.

Client-side verification of an `introductionV2`:

1. Parse the v2 intro.
2. Verify the Ed25519 signature under `LongTermKey`.
3. Verify the ML-DSA-65 signature under `LongTermKeyPQ`.
4. **For each PKG server's BLS pub key:** build the v2 attestation byte string from `(Username, LongTermKey, LongTermKeyPQ, lookup(LongTermMLKEMPub))`, and feed all of them into `bls.VerifyCompressed` with the intro's `ServerMultisig`. The lookup of `LongTermMLKEMPub` happens via the PKG's user-record endpoint (a cached read; the PKG never reveals it to network observers because the friend-request flow already encapsulates to it).

If step 4 fails, the intro is rejected.

## Migration plan

1. **PKG server software bumps to v2 attestation format.** Publishes new attestations alongside the old ones during a transition window; both Ed25519-only (v1) and Ed25519+PQ (v2) attestations are served on the user-record endpoint.
2. **Clients upgrade to verify v2 attestations.** During the transition window, clients try v2 first and fall back to v1 with a `event=pq.downgrade` log (per [US3 cutover instrumentation](../specs/001-pq-hybrid-crypto/tasks.md)). After the cutover instant set by `NEVERLUR_PQ_CUTOVER`, v1 attestations are rejected outright.
3. **PKG servers stop publishing v1 attestations** after the cutover date and all known PKG operators have moved.

## Threat-model impact

This extension closes the attestation-side gap in the option F hybrid friend-request design:

- v1 attestation present today: BLS break → attacker forges an attestation binding their own ML-DSA-65 / ML-KEM-768 pubs to a victim's username. Attacker can sign forged intros AND decapsulate the PQ half of future friend-request handshakes to that victim.
- v2 attestation: the same BLS break is required to forge, but the attacker also needs to break the user's R4 binding (cryptographic, not procedural — the PKG validates the R4 derivation against the Ed25519 seed before attesting). The attacker would need to either compromise the user's Ed25519 seed (giving them full identity takeover anyway) or break the HKDF-SHA512 R4 derivation (a separate primitive break).

Net result: v2 attestation makes "forge a hybrid identity binding" require all four of [BLS break, R4 derivation break, user-side Ed25519 compromise, network position] instead of just [BLS break, network position]. The forward-secrecy caveat called out in `wire-introduction-v2.md` (lossless static-ephemeral) is unaffected — that caveat is about *recovering* shared secrets, not about *forging* identity bindings.

## Open issues

- **BLS itself is classical and quantum-vulnerable.** The PKG attestation chain is still BLS-multisigned in v2. A future v3 attestation would replace BLS with a hybrid (BLS + post-quantum signature aggregation) scheme. CIRCL has no production-grade aggregatable PQ signature today; this is a longer-term research project. Until v3 lands, an adversary with quantum capability can forge PKG attestations; the option F design relies on the user's long-term ML-KEM key (which is R4-bound to their Ed25519 seed and never published in encapsulatable form to the public network) as the second line of defense.
- **PKG-side R4 validation requires the PKG to know users' Ed25519 seeds.** PKG already requires Ed25519 secret material to issue attestations (the PKG's role in Alpenhorn is to attest user identities via IBE-extracted private keys). Extending to require ML-KEM and ML-DSA seeds is a moderate operational change.
- **Migration storage cost.** The PKG's user record grows from 32 bytes (Ed25519 pub) to 32 + 1952 + 1184 = 3168 bytes. For PKGs with millions of users, that's a few GB of additional storage. Manageable but worth flagging.
- **Companion PR pairing.** This extension changes the PKG attestation surface that Gjallarhorn consumes (Gjallarhorn verifies the same attestations for conversation-mailbox encryption). Implementation requires paired PRs on both repos.

## Companion Gjallarhorn work

Gjallarhorn consumes `pkg.Attestation` to verify identity bindings for conversation initiators. Once Neverlur's v2 attestation lands, Gjallarhorn needs a paired PR that:

1. Bumps `go.mod` to the Neverlur version containing v2 attestation.
2. Updates Gjallarhorn's attestation verifier to require the v2 form (with the same cutover-date escape hatch during transition).
3. Adds tests for both v1-rejected-after-cutover and v2-accepted paths.

Tracking comment on Neverlur PR #4 lists this as a blocked-on-Neverlur-PR-#4-merge work item.
