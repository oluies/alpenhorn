# Implementation Plan: Post-Quantum Hybrid Cryptography

**Branch**: `001-pq-hybrid-crypto` | **Date**: 2026-05-23 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-pq-hybrid-crypto/spec.md`

## Summary

Move Neverlur's four cryptographic surfaces — `edtls/` server identity certificates, `config/` guardian-signed configuration chains, `keywheel/` per-relationship session secrets, and `friendrequest.go`/`addfriend.go`/`intro.go` friend-request KEM — from classical-only Ed25519 + X25519 to hybrid constructions: **Ed25519 + ML-DSA-65** for signatures and **X25519 + ML-KEM-768** for key encapsulation. The hybrid construction uses a transcript-binding KDF combiner so an adversary who later breaks one primitive family cannot decrypt or forge. The implementation uses Cloudflare CIRCL for all PQ primitives. Existing classical identities are preserved (the PQ half is generated and bound to the existing Ed25519 identity, not replacing it) and the migration ships with a per-deployment cut-over date after which classical-only artifacts are rejected.

## Technical Context

**Language/Version**: Go 1.25 (per `go.mod`)

**Primary Dependencies**:
- `github.com/cloudflare/circl/kem/mlkem/mlkem768` — ML-KEM-768 KEM (FIPS 203)
- `github.com/cloudflare/circl/sign/mldsa/mldsa65` — ML-DSA-65 signatures (FIPS 204)
- `crypto/ed25519` (stdlib) — classical signatures, retained
- `golang.org/x/crypto/curve25519` — explicit X25519 ECDH (replacing implicit `nacl/box` usage at the KEM boundary; `nacl/box` itself stays for the AEAD wrap below)
- `golang.org/x/crypto/nacl/box`, `golang.org/x/crypto/nacl/secretbox` — retained for AEAD wrapping under the hybrid-derived key
- `golang.org/x/crypto/hkdf` — HKDF-SHA512 combiner

**Storage**:
- On-disk client state under Badger (`pkg/`) and bbolt (`internal/`) — unchanged at storage layer; serialized records grow to carry hybrid key material.
- Long-term key files (`cmd/guardian/`, `cmd/neverlur-*/`) gain a paired PQ key file with the same lifecycle as the existing Ed25519 file.

**Testing**:
- `go test ./...` (existing). New test categories:
  - **KAT tests** in each new package (`pqsig/`, `pqkem/`, `hybrid/`) drawn directly from the FIPS 203 / FIPS 204 published test vectors.
  - **Differential half-compromise tests** in `hybrid/` that confirm session keys remain confidential when either the classical or PQ half is revealed.
  - **Cross-version protocol tests** in `addfriend/`, `dialing/`, `config/` exercising new↔new, new↔old (pre-cutover), and new↔old (post-cutover) handshakes.

**Target Platform**: Linux servers (coordinator, mixer, PKG, CDN, guardian) and any-OS Go clients. No platform-specific code.

**Project Type**: Single Go module with multiple packages and `cmd/` binaries. No frontend.

**Performance Goals** (from spec SC-007, tightened to 1.25× ceiling):
- Dialing round of 10k users: ≤ 1.25× current wall-clock.
- Add-friend round of 10k users: ≤ 1.25× current wall-clock.
- Friend-request end-to-end: ≤ 1.25× current wall-clock.

**Constraints**:
- Hybrid identity material must be bound at generation; the PQ half cannot be substituted post-hoc.
- After cutover date, classical-only artifacts rejected outright (no silent downgrade).
- Wire-format changes to `SignedConfig`, friend-request `introduction`, and edTLS server cert must each have a `docs/` design note (constitution Quality Gate).
- No `cgo`. No hand-rolled lattice math. CIRCL only.

**Scale/Scope**:
- ~5 packages added (`pqsig/`, `pqkem/`, `hybrid/`, plus extensions to `edtls/`, `config/`, `keywheel/`, `addfriend/`, top-level `friendrequest.go`/`intro.go`).
- ~12–15 binaries under `cmd/` need key-loading updates to accept the paired PQ key file.
- Estimated wire-size growth: friend-request introduction grows from 228 B to ≈ 6.5 KB (ML-KEM-768 pub 1184 B + ML-DSA-65 sig 3309 B + ML-DSA-65 pub 1952 B); signed configs grow by ≈ 5 KB per guardian signature.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Upstream Lineage Preserved | PASS | All inherited files retain `// Copyright 2015 David Lazar` headers. `NOTICE` will be updated to list `github.com/cloudflare/circl` (BSD-3-Clause) as a new third-party dependency. No license relaxation. |
| II. Threat Model Is Sacred | PASS | Hybrid construction strengthens the SOSP/OSDI threat model against the HNDL adversary without changing any other party's trust: PKGs see no additional plaintext, mixers see no additional correlation, the coordinator gains no metadata. Each affected PR will carry the mandated "threat-model impact" paragraph. |
| III. PQ Is Hybrid, Never Pure | PASS | Plan is hybrid-only: X25519 + ML-KEM-768, Ed25519 + ML-DSA-65, combined through a transcript-binding KDF. No pure-PQ code path exists at any layer. |
| IV. Crypto Is Imported, Not Invented | PASS | All primitives via CIRCL or Go stdlib. The combiner (`hybrid/` package) follows `draft-ietf-tls-hybrid-design` shape (concatenate-then-HKDF with full transcript binding) — no novel construction. KAT tests required per primitive. |
| V. Identity Continuity | PASS | Existing Ed25519 identity files are preserved; PQ key file is generated alongside and bound to the existing identity at generation. Hybrid clients verify both halves; pre-cutover, pure-classical peers degrade transparently and observably; post-cutover, rejected. No TOFU downgrade. |

**Quality Gates** (from constitution):
- `gofmt -l .` silence and `go vet ./...` green: enforced in CI (already wired in `.github/`).
- KAT additions for every new primitive integration: covered by Phase 1 contracts (`contracts/kat-mlkem768.md`, `contracts/kat-mldsa65.md`).
- Wire-format design notes in `docs/`: produced as part of Phase 1 (`docs/wire-signed-config-v2.md`, `docs/wire-introduction-v2.md`, `docs/wire-edtls-cert-v2.md`).

**Gate result**: PASS. No violations. No `Complexity Tracking` rows required.

## Project Structure

### Documentation (this feature)

```text
specs/001-pq-hybrid-crypto/
├── plan.md              # This file
├── spec.md              # Feature spec (already produced)
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── hybrid-combiner.md
│   ├── kat-mlkem768.md
│   ├── kat-mldsa65.md
│   ├── signed-config-v2.md
│   ├── introduction-v2.md
│   └── edtls-cert-v2.md
├── checklists/
│   └── requirements.md  # Spec quality checklist (already produced)
└── tasks.md             # Phase 2 output (/speckit-tasks command — not created here)
```

### Source Code (repository root)

The repo is a single Go module (`github.com/oluies/neverlur`). The plan adds three new packages, modifies four existing ones, and touches the top-level client code.

```text
# New packages
pqsig/                     # NEW. Ed25519 + ML-DSA-65 hybrid signature helpers.
├── pqsig.go               #   GenerateKey, Sign, Verify, key serialization.
├── pqsig_test.go
└── kat_test.go            #   KATs from FIPS 204 test vectors.

pqkem/                     # NEW. X25519 + ML-KEM-768 hybrid KEM helpers.
├── pqkem.go               #   GenerateKey, Encapsulate, Decapsulate.
├── pqkem_test.go
└── kat_test.go            #   KATs from FIPS 203 test vectors.

hybrid/                    # NEW. The transcript-binding combiner.
├── combiner.go            #   HKDF-SHA512 over both shared secrets + transcript.
├── combiner_test.go       #   Half-compromise differential tests.
└── doc.go

# Modified packages
edtls/
├── server.go              # MODIFIED. Cert now carries Ed25519 cert + ML-DSA-65 pubkey extension + ML-DSA-65 signature extension.
├── client.go              # MODIFIED. Verifies both halves.
├── doc.go                 # MODIFIED. Documents hybrid cert format.
├── cert_v2.go             # NEW. X.509 extension OIDs, marshal/unmarshal of PQ extensions.
├── cert_v2_test.go        # NEW.
├── client_test.go
└── server_test.go         # MODIFIED. Adds new↔new and post-cutover rejection tests.

config/
├── config.go              # MODIFIED. Guardian gains PQ key field; SignedConfig signature map carries hybrid sigs; verifier requires both.
├── client.go
├── config_easyjson.go     # REGENERATED.
├── persist.go
├── server.go              # MODIFIED. Cutover-date enforcement on writes.
├── server_test.go
└── config_test.go         # MODIFIED. Mixed-version chain tests.

keywheel/
├── keywheel.go            # MODIFIED. Put() unchanged at signature; callers feed hybrid-derived [32]byte. Doc updated.
├── keywheel_easyjson.go
└── keywheel_test.go       # MODIFIED. Adds a test that the secret fed to Put is rejected if it has the wrong derivation domain tag.

addfriend/
└── mixer.go               # MODIFIED. SizeIntro updated; SizeEncryptedIntro recomputed.

# Top-level (package neverlur)
intro.go                   # MODIFIED. introduction struct gains MLKEMPublicKey, MLDSAPublicKey, MLDSASignature fields; binary layout v2.
intro_test.go              # NEW.
friendrequest.go           # MODIFIED. OutgoingFriendRequest / IncomingFriendRequest carry hybrid-paired key material; ExpectedKey becomes a hybrid identity.
addfriend.go               # MODIFIED. genIntro() generates X25519 + ML-KEM-768 ephemerals; newFriend() runs hybrid combiner to derive keywheel seed.

# Binaries (key-loading only)
cmd/guardian/neverlur-guardian-keygen/main.go        # MODIFIED. Generates Ed25519 + ML-DSA-65 paired key files.
cmd/guardian/neverlur-guardian-sign-config/main.go   # MODIFIED. Signs with both keys.
cmd/guardian/guardian.go                             # MODIFIED. Verifies both signatures on incoming configs.
cmd/neverlur-coordinator/main.go                     # MODIFIED. Loads paired identity.
cmd/neverlur-mixer/main.go                           # MODIFIED. Loads paired identity.
cmd/neverlur-pkg/main.go                             # MODIFIED. Loads paired identity.
cmd/neverlur-cdn/main.go                             # MODIFIED. Loads paired identity.

# Wire-format design notes (required by constitution)
docs/
├── wire-signed-config-v2.md   # NEW.
├── wire-introduction-v2.md    # NEW.
└── wire-edtls-cert-v2.md      # NEW.

# Third-party attribution
NOTICE                          # MODIFIED. Add cloudflare/circl entry.
```

**Structure Decision**: Single-module Go layout, as already established. No new top-level directory beyond `pqsig/`, `pqkem/`, `hybrid/`, and `docs/` (the latter for wire-format design notes mandated by the constitution). All existing package paths under `github.com/oluies/neverlur/...` are preserved. No `internal/` reshuffling.

## Complexity Tracking

> Constitution Check passed without violations. No rows required.
