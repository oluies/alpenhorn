# Phase 0 Research: Post-Quantum Hybrid Cryptography

**Feature**: 001-pq-hybrid-crypto
**Date**: 2026-05-23

This document resolves every open technical question raised by the plan's Technical Context section. Every decision below feeds directly into Phase 1 design.

---

## R1. PQ KEM parameter set

**Decision**: ML-KEM-768 (CIRCL `kem/mlkem/mlkem768`).

**Rationale**: The constitution (Principle III) names ML-KEM-768 explicitly. It is NIST-Category-3 security, balances key/ciphertext size (pub 1184 B, ct 1088 B) against performance, and is the recommended default in `draft-ietf-tls-hybrid-design` and BoringSSL's hybrid choice. ML-KEM-512 saves ~30% wire but drops to Category 1 — insufficient for long-term confidentiality of stored traffic. ML-KEM-1024 buys little additional security at the cost of doubling the ciphertext footprint inside the friend-request introduction, which is already the dominant wire-size concern.

**Alternatives considered**:
- ML-KEM-512: rejected (insufficient long-term margin; constitution names 768).
- ML-KEM-1024: rejected (no real-world threat motivates Category 5; wire-cost worse for the round-bounded mixers).
- Classic McEliece: rejected (multi-MB public keys — incompatible with the wire budget).

---

## R2. PQ signature parameter set

**Decision**: ML-DSA-65 (CIRCL `sign/mldsa/mldsa65`).

**Rationale**: Constitution names ML-DSA-65. Category 3, public key 1952 B, signature 3309 B. ML-DSA-44 is faster but Category 2; ML-DSA-87 doubles signature size for marginal gain. The signed-config artifact carries one signature per guardian; with 3–5 guardians typical, ML-DSA-65 adds ~10–16 KB per config, acceptable for a long-poll CDN-distributed object.

**Alternatives considered**:
- ML-DSA-44 / ML-DSA-87: rejected per above.
- SLH-DSA (SPHINCS+): rejected. Signatures are 8–50 KB depending on parameter set, which is intolerable for the friend-request introduction. SLH-DSA remains a future fallback if ML-DSA is ever broken, but is not part of this migration.
- Falcon (FN-DSA): rejected. CIRCL support is partial; floating-point side-channel concerns; NIST standardization not yet final at FIPS-spec parity as of 2026-05.

---

## R3. Combiner construction

**Decision**: HKDF-SHA512(salt = transcript_hash, ikm = `ssX25519 || ssMLKEM`, info = `"neverlur/v1 hybrid kdf " || context_label`), with full transcript binding.

For the **KEM combiner** (`hybrid.CombineKEM`):
- `ssX25519` = the 32-byte X25519 shared secret.
- `ssMLKEM` = the 32-byte ML-KEM-768 shared secret.
- `transcript_hash` = SHA-512 over the concatenation of (sender X25519 pub, sender ML-KEM pub, recipient X25519 pub, ML-KEM ciphertext, both long-term hybrid identity public keys, dialing round number).
- `context_label` is one of `"friend-request"`, `"keywheel-seed"`, `"edtls-session"`, distinguishing call sites so the same primitive material cannot be cross-used.
- Output 32 bytes — drop-in compatible with `keywheel.Wheel.Put`.

For the **signature combiner** (`pqsig.Verify`):
- Not a KDF; instead, the verifier requires `Ed25519.Verify(edKey, msg, edSig) && MLDSA65.Verify(pqKey, msg, pqSig)` where `msg` includes a domain separator (`"neverlur-hybrid-sig-v1"` || canonical bytes of the artifact || classical-pub-hash || pq-pub-hash). The classical-pub-hash and pq-pub-hash bind the two keys together so a substitution attack on either is detected.

**Rationale**: This is the same shape as `draft-ietf-tls-hybrid-design` (concatenate-then-KDF), generalized to bind a transcript so an attacker who replays one component into a different context cannot succeed. SHA-512 is chosen for combiner output to give 256-bit security headroom against quantum collision attacks; HMAC-SHA256 inside HKDF is preserved for performance.

**Alternatives considered**:
- XOR of the two shared secrets: rejected (does not preserve IND-CCA in the presence of malleability).
- "Hash both then XOR" (Chempat): viable but more complex; HKDF with transcript binding is the IETF-blessed minimum and is what CIRCL examples follow.
- Native CIRCL `hpke` hybrid suites: considered, but they cover only the HPKE recipient/sender model, not the long-term-identity+ephemeral pattern Alpenhorn uses for the introduction step.

---

## R4. Hybrid identity binding

**Decision**: A hybrid identity is the pair `(edPub: ed25519.PublicKey, pqPub: mldsa65.PublicKey)`. The two halves are bound at generation by:
1. Generating `edPub` first.
2. Generating `pqPub` with seed derived from `HKDF-SHA512(edPriv-as-seed, "neverlur/v1 pq-id-binding")` — making the PQ keypair deterministically reproducible from the Ed25519 seed AND ensuring an attacker cannot present a forged Ed25519 key paired with someone else's PQ key (because the Ed25519 owner must sign their own pairing).
3. The canonical "hybrid public key" wire representation is `edPub || pqPub` (32 + 1952 = 1984 bytes) prefixed by a one-byte version tag.

The introduction, signed-config Guardian record, and edTLS cert all carry both halves and verify both halves. There is no way to express a hybrid identity with only one half.

**Rationale**: Deterministic PQ derivation from the existing Ed25519 seed lets every existing identity in a running deployment (guardians, mixers, PKG, CDN, clients) gain its PQ half on first upgrade without re-bootstrapping trust. The Ed25519 owner is the only party who can produce the matching PQ key, so the binding cannot be forged by a third party.

**Alternatives considered**:
- Independent random PQ key: rejected. Would require an out-of-band attestation that the PQ key belongs to the Ed25519 identity, requiring a new trust ceremony for every existing user.
- Single combined seed for both: rejected. Breaks identity continuity (the existing Ed25519 key would have to be regenerated to match).

---

## R5. Wire-format strategy for `SignedConfig`

**Decision**: Bump `SignedConfigVersion` from 1 to 2. Version-2 records have:
- An extended `Guardian` struct with `Key ed25519.PublicKey` AND `PQKey mldsa65.PublicKey`.
- A `Signatures` map whose value is a `HybridSignature` struct (`{Ed [64]byte; PQ [3309]byte}`) instead of a raw `[]byte`.
- A new `MinClientVersion` field naming the minimum protocol version that may consume this config.

Old (v1) configs continue to parse and verify with classical-only checks **until the cut-over date passes**, after which `Verify()` and `VerifyConfigChain()` reject any v1 record. The cut-over date is a deployment-level constant (`config.CutoverDate`) read from environment / config file at process start.

**Rationale**: A clean version bump avoids the trap of optional-field ambiguity (where an attacker strips the PQ field and downgrades). The single `MinClientVersion` field is the network's hard knob for ending the transition.

**Alternatives considered**:
- Add `SignaturesPQ` as a sibling map next to `Signatures`: rejected. An attacker who deletes the `SignaturesPQ` field can trick a pre-cutover client into accepting a downgrade. A struct-typed value forces both halves to travel together.
- Smuggle the PQ signature inside the existing `[]byte` via a length-prefixed inner blob: rejected. Same downgrade risk, plus it hides the schema from `easyjson`-generated code.

---

## R6. Wire-format strategy for `introduction`

**Decision**: Bump introduction binary layout to v2. The v2 struct is:

```go
type introductionV2 struct {
    Version          byte         // = 2
    Username         [64]byte
    DHPublicKey      [32]byte     // X25519 ephemeral pub (unchanged role)
    MLKEMPublicKey   [1184]byte   // ML-KEM-768 ephemeral pub
    DialingRound     uint32
    LongTermKey      [32]byte     // Ed25519 (unchanged)
    LongTermKeyPQ    [1952]byte   // ML-DSA-65
    Signature        [64]byte     // Ed25519
    SignaturePQ      [3309]byte   // ML-DSA-65
    ServerMultisig   [32]byte
}
```

`SizeIntro` becomes 6695 bytes (up from 228). `SizeEncryptedIntro` is recomputed accordingly. The IBE ciphertext budget (BLS12-381 G1 over the intro plaintext) grows by ~29×, with measurable but bounded impact on mailbox sizes; this is the largest wire change in the migration and is the dominant input to SC-007.

The marshaler refuses any payload whose first byte is not the expected version. A v1 intro and a v2 intro never collide because v1's first byte is the first byte of `Username` (which is the high byte of a 64-byte identity — never 0x02 in practice, but we additionally reject any record with a v1 length).

**Rationale**: Same downgrade-resistance argument as R5. Constitution Principle III names the friend-request handshake explicitly; the wire format must be hybrid by construction, not by optional fields.

**Alternatives considered**:
- Out-of-band PQ public-key fetch (intro carries only a hash, full key fetched from a directory): rejected. Introduces a new directory dependency in the cold path, defeats the PIR-style anonymity-set property (the directory lookup leaks who is being contacted).
- Smaller `LongTermKeyPQ` via key-compression: rejected. ML-DSA does not have a useful compression primitive; CIRCL exposes only the canonical 1952-byte form.

---

## R7. Wire-format strategy for edTLS certificates

**Decision**: The cert remains a self-signed X.509 over the Ed25519 key (preserving compatibility with the underlying `crypto/tls` machinery), with two custom extensions:

- OID `1.3.6.1.4.1.99999.1.1` (TBD: assign under Neverlur's private enterprise OID arc, documented in `docs/wire-edtls-cert-v2.md`): `pqPublicKey` — the ML-DSA-65 public key bytes.
- OID `1.3.6.1.4.1.99999.1.2`: `pqSignature` — an ML-DSA-65 signature over `SHA-512(tbsCertificate) || pqPublicKey`, produced by the same key whose public form appears in extension 1.

Both extensions are marked critical, so a verifier that does not understand them rejects the cert. The classical Ed25519 self-signature is verified by `cert.CheckSignatureFrom(cert)` as today. The PQ signature is verified additionally; both must succeed.

**Rationale**: Keeps `crypto/tls` and `crypto/x509` happy (we are not inventing a new transport), while delivering the constitution's "hybrid Ed25519 + ML-DSA-65 identity binding" requirement. Marking extensions critical is the standards-conformant way to reject classical-only verifiers.

**Alternatives considered**:
- A separate dual-TLS handshake carrying a parallel PQ-cert: rejected. Doubles the connection setup, fights `crypto/tls`, and gains nothing.
- Carry PQ key/sig in TLS extension blocks (e.g., a custom Encrypted Extensions): rejected. Go's `crypto/tls` does not expose hooks to inject arbitrary extensions; cgo wraps to BoringSSL are forbidden by constitution Principle IV.

---

## R8. Cutover-date mechanism

**Decision**: Each binary reads `NEVERLUR_PQ_CUTOVER` from environment (RFC 3339 timestamp) at startup. The value also lives in `config.SignedConfig.Inner` for the relevant services so every operator-facing record carries it. Before the cutover instant, classical-only artifacts are accepted with a structured warning log (`event=pq.downgrade`, `peer=…`, `artifact=…`). After it, they are rejected with `event=pq.reject`.

Operator query surface: a new `cmd/neverlur-pq-posture` CLI walks a config chain and produces a tabular report of "hybrid / classical / unverifiable" for each peer and each guardian signature. This satisfies SC-005 (operator can produce a posture report in under 5 minutes).

**Rationale**: A single deployment-level knob is the simplest realization of FR-014. Environment variable + config-record echoing avoids accidental drift between operator intent and on-the-wire policy.

**Alternatives considered**:
- Per-peer cutover via signed configuration: rejected (more complex, no real use case — operators want one switch).
- Hard-coded build-time cutover: rejected (forces a code release to change policy).

---

## R9. Key-material on-disk format

**Decision**: A single new file format per identity, suffix `.neverlur-id-v2`, containing a JSON record:

```json
{
  "version": 2,
  "ed25519_seed":  "<base64, 32 bytes>",
  "mldsa65_seed":  "<base64, 32 bytes — derived from ed25519_seed per R4 but stored explicitly for fast load>",
  "created":       "2026-05-23T00:00:00Z",
  "rotated_from":  null
}
```

On first run of an upgraded binary, if only the legacy single-key file exists, the binary derives the PQ seed per R4, writes the new file alongside (without deleting the old file), and logs `event=pq.identity.upgraded`. The old file remains for rollback.

**Rationale**: Atomic upgrade-in-place, no operator action required for the common case. Storing both seeds explicitly (rather than re-deriving on every load) avoids HKDF cost in the hot path and makes the file self-contained for backup tooling.

**Alternatives considered**:
- Two separate files (`.ed25519` + `.mldsa65`): rejected — risks the two files diverging via a partial filesystem operation, breaking the binding from R4.
- PKCS#8 / PEM container: rejected — adds parsing surface for no gain inside a private-deployment file format.

---

## R10. Test strategy for half-compromise

**Decision**: The `hybrid/` package ships `combiner_test.go` with two tests:

1. `TestSessionKeyResistsClassicalCompromise`: runs a full Encapsulate/Decapsulate round, then deliberately discloses `ssX25519` to a "compromised" verifier and asserts the verifier still cannot produce the combined key without `ssMLKEM`.
2. `TestSessionKeyResistsPQCompromise`: symmetric — discloses `ssMLKEM` and confirms the verifier still cannot produce the combined key without `ssX25519`.

Both tests assert the bytewise output of the combiner is different from `ssX25519` alone and different from `ssMLKEM` alone, and additionally that the combiner output collapses to neither component under any rearrangement of input order.

A higher-level `addfriend_e2e_test.go` runs a full friend-request exchange and asserts that the keywheel seed it produces matches an independently computed combiner output, end-to-end.

**Rationale**: Direct test-level satisfaction of SC-003 and SC-004.

---

## R11. CIRCL version pinning

**Decision**: Pin to a specific tagged CIRCL release in `go.mod` (target: latest `v1.x` stable as of branch creation, currently `v1.7.0`). Dependabot continues to manage upgrades, but a major-version bump in CIRCL must be reviewed manually because PQ primitive APIs are not yet fully frozen across versions.

**Rationale**: CIRCL is the single source of PQ primitives per constitution IV; pinning gives us a known KAT-pass surface and avoids transitive-update surprises.

**Alternatives considered**:
- Go stdlib `crypto/mlkem` (added in Go 1.24): rejected as **primary** because no stdlib ML-DSA-65 yet; mixing one stdlib + one CIRCL primitive complicates the combiner and KAT story. Keep stdlib as a future swap target once both primitives are in stdlib.

---

## R12. Performance budget validation

**Decision**: A `benchmarks/` directory under each affected package, with `Benchmark*` functions that produce wall-clock numbers for:
- Single hybrid friend-request handshake (init + verify).
- Hybrid signed-config verification with N=5 guardians.
- 10k-user dialing round mixer step.
- 10k-user add-friend round mixer step.

CI publishes the numbers and compares them against a captured pre-migration baseline. If any number exceeds 1.25× baseline, the build fails. The planning-phase escape hatches in SC-007 (parameter-set adjustment, bottleneck identification, operator sign-off) trigger only after a measured violation.

**Rationale**: Direct test-level satisfaction of SC-007. Captures the budget in CI rather than in folklore.

---

## Open items

None. All NEEDS CLARIFICATION items from the spec are resolved.
