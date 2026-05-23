# Phase 1 Data Model: Post-Quantum Hybrid Cryptography

**Feature**: 001-pq-hybrid-crypto
**Date**: 2026-05-23

This document specifies every persistent and on-wire data structure changed or added by this migration. Field-level validation rules are stated where they exist; state transitions are described per entity.

---

## E1. HybridIdentity (in-memory)

**Purpose**: Canonical paired representation of a long-term identity used by guardians, mixers, PKG, CDN, coordinator, and clients.

**Fields**:
- `EdPub  ed25519.PublicKey`  (32 bytes; required)
- `EdPriv ed25519.PrivateKey` (64 bytes; required for signing roles, absent for verify-only roles)
- `PQPub  mldsa65.PublicKey`  (1952 bytes; required)
- `PQPriv mldsa65.PrivateKey` (4032 bytes; required for signing roles)
- `Created time.Time`          (required)

**Invariants**:
- `mldsa65.NewKeyFromSeed(HKDF-SHA512(EdPriv-seed, "neverlur/v1 pq-id-binding")) == (PQPub, PQPriv)` (R4). On every load, verify the binding; reject the file with a structured error if it fails.
- `EdPub` matches `ed25519.PrivateKey(EdPriv).Public()`.

**Lifecycle**:
- *Generation* (first run on upgraded binary, or first run of new keygen tool): derive `PQPriv` from `EdPriv` seed, persist via E2.
- *Load*: read E2 file; re-verify the R4 binding; populate in memory.
- *Rotation*: write a new E2 file with a fresh `EdPriv`/derived `PQPriv` and a non-nil `rotated_from` reference. The old identity remains valid for verification of its own past artifacts until the operator removes it.

---

## E2. IdentityFile (on disk)

**Purpose**: Persistent on-disk representation of a HybridIdentity. Format described in research R9.

**Fields**:
- `Version       int`         (= 2; required; rejected if missing or != 2)
- `Ed25519Seed   []byte`      (base64; 32 bytes; required)
- `MLDSA65Seed   []byte`      (base64; 32 bytes; required; must satisfy R4 binding)
- `Created       time.Time`   (RFC 3339; required)
- `RotatedFrom   *string`     (optional; path or hash of the prior identity file)

**Validation**:
- Reject if file mode is group- or world-readable (chmod 0600 expected).
- Reject if Version != 2.
- Reject if R4 binding check fails.

**Transition from v1**:
- A v1 file is the legacy 32-byte Ed25519 seed (or PEM-encoded equivalent depending on which binary wrote it).
- On detection: derive `MLDSA65Seed` per R4, write v2 file alongside (`<basename>.neverlur-id-v2`), leave the v1 file untouched, log `event=pq.identity.upgraded`. Subsequent loads prefer the v2 file.

---

## E3. HybridKEMKeypair (in-memory, ephemeral)

**Purpose**: Per-friend-request and per-edTLS-session ephemeral KEM material.

**Fields**:
- `X25519Pub  [32]byte`        (required)
- `X25519Priv [32]byte`        (required, zeroized after use)
- `MLKEMPub   mlkem768.PublicKey`  (1184 bytes; required)
- `MLKEMPriv  mlkem768.PrivateKey` (2400 bytes; required, zeroized after use)

**Lifecycle**:
- Created by initiator per friend request and per edTLS handshake.
- Public halves go into `introductionV2` or the edTLS cert extension.
- Private halves live in memory only; deleted as soon as the keywheel seed is derived.

---

## E4. HybridSignature (wire + in-memory)

**Purpose**: Pair of signatures over the same canonical message, both required to verify.

**Fields**:
- `Ed [64]byte`        (Ed25519 signature; required)
- `PQ [3309]byte`      (ML-DSA-65 signature; required)

**Wire encoding** (inside `SignedConfig.Signatures` map and `introductionV2`):
- Fixed-width concatenation `Ed || PQ` (3373 bytes total). No length prefix needed because both halves are fixed-size for the chosen parameter sets.

**Validation**:
- A `HybridSignature` is valid iff `ed25519.Verify(edKey, msg, sig.Ed) && mldsa65.Verify(pqKey, msg, sig.PQ)`, where `msg` carries the domain separator and the SHA-512 hashes of both public keys (R3).
- Any verifier that succeeds on one component and fails on the other MUST return a `HybridVerifyError` distinguishing which half failed (for operator diagnostics) but MUST treat the artifact as rejected.

---

## E5. SignedConfig v2 (modified)

**Purpose**: Hash-chained, multi-guardian-signed configuration record for AddFriend, Dialing, and Convo services.

**Fields (v2 changes only — full struct in `contracts/signed-config-v2.md`)**:
- `Version int` (= 2)
- `Service string` (unchanged)
- `Created, Expires time.Time` (unchanged)
- `PrevConfigHash string` (unchanged; SHA-512 over canonical encoding of the prior v2 record)
- `Inner InnerConfig` (unchanged)
- `Guardians []Guardian` where `Guardian = {Username string, Key ed25519.PublicKey, PQKey mldsa65.PublicKey}`
- `Signatures map[string]HybridSignature` (was `map[string][]byte`)
- `MinClientVersion int` (NEW; default 2)

**Invariants**:
- For each guardian listed in the *previous* config and for each new guardian in the *current* config, `Signatures` MUST contain a `HybridSignature` keyed by base32-encoded `Guardian.Key`, and that `HybridSignature` MUST verify under both `Guardian.Key` and `Guardian.PQKey`.
- `PrevConfigHash` of config N equals `SHA-512` over the canonical bytes of config N-1 (signatures stripped).

**State transitions**:
- A v1 config is accepted with a warning (`event=pq.downgrade`) until the cutover instant; rejected with `event=pq.reject` after.
- A v2 config with `MinClientVersion > peer.SupportedVersion` is rejected by that peer.

---

## E6. Guardian (modified)

**Purpose**: Identity of a party authorized to sign configuration chains.

**Fields**:
- `Username string`           (required)
- `Key      ed25519.PublicKey` (32 bytes; required; same field name as v1 for source-code continuity)
- `PQKey    mldsa65.PublicKey` (1952 bytes; required in v2)

**Invariants**:
- `(Key, PQKey)` MUST satisfy the R4 binding when the guardian self-publishes a key-attestation (operator-side check; verifiers cannot enforce this without the seed but do reject any guardian whose attestation fails).

---

## E7. introduction v2 (modified, wire-layout-significant)

**Purpose**: The "public" part of a friend-request — what the initiator publishes via IBE-encrypted onion into the recipient's mailbox.

**Wire layout** (big-endian, fixed-width; total 6695 bytes):

| Offset | Length | Field             | Meaning |
|-------:|-------:|-------------------|---------|
|      0 |      1 | `Version`         | = 2 |
|      1 |     64 | `Username`        | recipient identity |
|     65 |     32 | `DHPublicKey`     | initiator X25519 ephemeral pub |
|     97 |   1184 | `MLKEMPublicKey`  | initiator ML-KEM-768 ephemeral pub |
|   1281 |      4 | `DialingRound`    | uint32 |
|   1285 |     32 | `LongTermKey`     | initiator Ed25519 long-term pub |
|   1317 |   1952 | `LongTermKeyPQ`   | initiator ML-DSA-65 long-term pub |
|   3269 |     64 | `Signature`       | Ed25519(msg) |
|   3333 |   3309 | `SignaturePQ`     | ML-DSA-65(msg) |
|   6642 |     32 | `ServerMultisig`  | BLS multisig over (key, username, longterm) attestations (unchanged role) |
|   6674 |     21 | reserved          | zero-padding to round to a multiple of 7 for the IBE chunking helper |

**Signed message** (`msg`):

```
"NeverlurIntroductionV2"
|| Version (1 byte)
|| Username (64)
|| DHPublicKey (32)
|| MLKEMPublicKey (1184)
|| DialingRound (4)
|| SHA512(LongTermKey || LongTermKeyPQ) (64)
```

Including the hash of both long-term keys in the signed message implements the R4 binding at the introduction level: an attacker who substitutes the PQ key for a different one invalidates the signature.

**Validation**:
- `Version` MUST be 2; otherwise reject (do not fall back to v1 parser unless the peer is pre-cutover and the v1 byte heuristic passes).
- `Signature` MUST verify under `LongTermKey`; `SignaturePQ` MUST verify under `LongTermKeyPQ`; the BLS multisig in `ServerMultisig` MUST verify under the round's PKG server set (unchanged).
- All three checks MUST succeed; failure of any one is treated as a forged intro.

---

## E8. edTLS certificate v2 (modified, wire-layout-significant)

**Purpose**: Self-signed X.509 certificate bound to a server's HybridIdentity, presented during the TLS 1.3 handshake to the peer.

**Structure**:
- Standard X.509v3 cert; `SubjectPublicKeyInfo` carries the Ed25519 public key (unchanged).
- Self-signed with the Ed25519 private key (unchanged).
- **Extension 1** (critical, OID TBD-`neverlur.pqPublicKey`): DER-encoded `OCTET STRING` containing the 1952-byte ML-DSA-65 public key.
- **Extension 2** (critical, OID TBD-`neverlur.pqSignature`): DER-encoded `OCTET STRING` containing the 3309-byte ML-DSA-65 signature over `SHA-512(tbsCertificate) || pqPublicKeyBytes`.

**Validation**:
- Standard X.509 self-signed Ed25519 check (unchanged).
- Both extensions MUST be present, critical, and parse cleanly.
- ML-DSA-65 signature MUST verify under the embedded ML-DSA-65 public key over `SHA-512(tbsCertificate) || pqPublicKeyBytes`.
- The R4 binding between Ed25519 and ML-DSA-65 keys is not verified at cert-validation time (the verifier lacks the seed), but the operator-side tooling (`neverlur-pq-posture`) flags certs whose halves were not generated with the binding.

---

## E9. Keywheel session secret (semantics unchanged; derivation changed)

**Purpose**: `keywheel.Wheel.Put(username, round, secret *[32]byte)` accepts the initial secret for a friendship; the wheel ratchets forward per round.

**Field of interest**:
- `secret *[32]byte` — the input to `Put` and the per-round output of `SessionKey`.

**Change**: The `[32]byte` type, on-disk layout, and ratchet (HMAC-SHA256 chain) are unchanged. What changes is `newFriend()`:

Before:
```
sharedKey := new([32]byte)
box.Precompute(sharedKey, in.DHPublicKey, sent.DHPrivateKey)
c.wheel.Put(in.Username, in.DialRound, sharedKey)
```

After:
```
ssX25519 := curve25519.X25519(sent.DHPrivateKey[:], in.DHPublicKey[:])
ssMLKEM, err := mlkem768.Decapsulate(sent.MLKEMPrivateKey, in.MLKEMCiphertext)
sharedKey := hybrid.CombineKEM(hybrid.ContextKeywheelSeed, transcript, ssX25519, ssMLKEM)
c.wheel.Put(in.Username, in.DialRound, sharedKey)
```

`transcript` carries both hybrid identity public keys and the dialing round, satisfying R3.

**Invariant**: A keywheel entry produced post-migration MUST be derived through `hybrid.CombineKEM` with `ContextKeywheelSeed`. A keywheel test (`TestKeywheelRejectsRawClassicalSecret`) asserts that any seed not produced via the combiner is detectable in debug builds (the combiner writes a 32-byte tag into the wheel's internal version byte slot to mark the construction; the slot is the existing `version` byte in `keywheel.go` extended to a 16-byte header).

---

## E10. OutgoingFriendRequest / sentFriendRequest / IncomingFriendRequest (modified)

**Purpose**: Client-side records of friend-request lifecycle.

**Field changes**:

`OutgoingFriendRequest`:
- `ExpectedKey ed25519.PublicKey` → `ExpectedIdentity HybridIdentityPublic` (a small struct carrying both `EdPub` and `PQPub`; nullable as today when the recipient's identity is unknown).

`sentFriendRequest`:
- Adds `MLKEMPrivateKey mlkem768.PrivateKey` and `MLKEMPublicKey mlkem768.PublicKey` alongside the existing `DHPublicKey` / `DHPrivateKey` pair.

`IncomingFriendRequest`:
- Adds `MLKEMCiphertext mlkem768.Ciphertext` carrying the encapsulation produced by the recipient over the initiator's ML-KEM public key.

**Persistence**: easyjson regeneration required for `client_json.go` and `keywheel/keywheel_easyjson.go`.

---

## E11. PQ Migration Posture (operator-facing entity)

**Purpose**: Per-peer, per-artifact attribute observable by operators (spec FR-013).

**Fields**:
- `Peer string` (username or service endpoint)
- `Artifact string` (one of `"edtls-cert"`, `"signed-config"`, `"introduction"`, `"identity"`)
- `Status enum` (`"hybrid"`, `"classical-only"`, `"unverifiable"`)
- `ObservedAt time.Time`
- `Detail string` (free-form: which half failed, which OID was missing, etc.)

**Source**: produced by the new `cmd/neverlur-pq-posture` CLI tool walking the live config chain and a snapshot of currently connected peers. Output is JSON for tool integration and a tabular human view.

---

## Relationships

```
HybridIdentity (E1) ──persisted-as──> IdentityFile (E2)
                  ├──appears-in──> Guardian (E6) ──in──> SignedConfig v2 (E5)
                  ├──signs────────> HybridSignature (E4) ──in──> SignedConfig v2 (E5)
                  └──signs────────> introduction v2 (E7) (via LongTermKey + LongTermKeyPQ)

HybridKEMKeypair (E3) ──ephemeral──> introduction v2 (E7) (via DHPublicKey + MLKEMPublicKey)
                       ──combined-via──> hybrid.CombineKEM ──> Keywheel seed (E9)

HybridIdentity (E1) ──signs──> edTLS cert v2 (E8) (Ed25519 self-sign + ML-DSA-65 extension sig)

All entities ──observed-by──> PQ Migration Posture (E11) via cmd/neverlur-pq-posture
```
