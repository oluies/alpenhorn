# Neverlur Constitution

Neverlur is a post-quantum fork of Alpenhorn. Its purpose is to evolve the
original friend-discovery layer of the Vuvuzela / Alpenhorn metadata-private
messaging stack to remain secure against "harvest-now, decrypt-later"
adversaries with future quantum capability, without weakening the privacy
guarantees of the upstream design. Neverlur is paired with Gjallarhorn (fork
of Vuvuzela); the two evolve together.

## Core Principles

### I. Upstream Lineage Is Preserved
Every file inherited from upstream Alpenhorn keeps its original
`// Copyright 2015 David Lazar` (and later) header verbatim. The AGPL-3.0
license is never relaxed, dual-licensed, or replaced. The `NOTICE` file at
the repo root stays current: every new third-party dependency is listed
with its license. The companion service Gjallarhorn (fork of Vuvuzela) is
held to the same standard. Lineage is not a chore; it is a precondition
for the fork's legitimacy.

### II. The Threat Model Is Sacred
Two threat models bind this codebase: the SOSP 2015 Vuvuzela mixnet model
(differentially private noise, multi-server anonymity, encrypted dead
drops, no single party trusted with metadata) and the OSDI 2016 Alpenhorn
friend-discovery model — keyword-private discovery, anonymous PIR-style
lookups, key-wheel forward secrecy, and the property that learning who
two users are about to talk to requires compromising every PKG, every
mixer, and the coordinator across the same round. No change is permitted
that weakens either model. Friend-discovery leaks (a malicious PKG
learning who Alice is calling, a CDN learning who downloaded which
config, a mixer correlating dial rounds across days) are P0 bugs. Every
PR touching crypto, networking, the key wheel, or the friend-request /
dialing protocols must include an explicit "threat-model impact"
paragraph in its description. Upstream paper:
https://davidlazar.org/papers/alpenhorn.pdf.

### III. Post-Quantum Is Hybrid, Never Pure (NON-NEGOTIABLE)
Cryptographic primitives migrate to **hybrid** constructions — classical
(X25519, Ed25519) and post-quantum (ML-KEM-768, ML-DSA-65) running side
by side, combined through a KDF that binds both transcripts. Pure-PQ
deployments are forbidden until ML-KEM and ML-DSA have at least five
years of unbroken production deployment across the industry. The specific
surfaces being migrated in Neverlur are:

- **edTLS server certificates** (`edtls/`): hybrid Ed25519 + ML-DSA-65
  identity bindings; classical and PQ public keys both embedded, both
  verified.
- **Signed configuration chains** (`config/`): every `SignedConfig`
  carries paired classical + PQ signatures from each guardian; verifiers
  require both.
- **Key-wheel session keys** (`keywheel/`): per-round shared secrets
  derived from a hybrid X25519 + ML-KEM-768 combiner; forward secrecy
  preserved on both halves.
- **Friend-request handshake** (`addfriend/`, `friendrequest.go`): PIR
  blob and PKG-extracted key material both use the hybrid combiner; the
  ciphertext size budget accommodates ML-KEM-768.

Lattice cryptanalysis is young; classical primitives are the belt under
the suspenders.

### IV. Cryptographic Code Is Imported, Not Invented
All KEM, signature, and AEAD primitives come from vetted libraries:
`github.com/cloudflare/circl`, `golang.org/x/crypto`, or the Go standard
library. No hand-rolled lattice math, no cgo wrappers around C crypto,
no toy reimplementations "for performance." Every primitive integration
ships with Known-Answer Tests (KATs) drawn from the relevant NIST
specification or IETF draft. The hybrid combiner follows the IETF
`draft-ietf-tls-hybrid-design` style and is the only place where
primitives meet.

### V. Identity Continuity
A user's long-term identity may be rotated but **never silently
downgraded**. Once a user has presented a PQ-augmented identity, every
subsequent friend-request, key-wheel epoch, and dialing round signed
under that identity must remain verifiable by hybrid-aware clients
throughout any transition window. Pure-classical clients see classical
proofs; hybrid clients see both and require both. Friend-list state is
migrated, not invalidated: an Alpenhorn-era friendship survives the
upgrade with the classical key bound to the new hybrid identity, never
replaced by an unverified PQ key. A "trust-on-first-use" downgrade path
that drops the PQ half is a constitutional violation regardless of how
convenient it would make rollout.

## Compatibility and Coordination

Neverlur does not exist alone. Gjallarhorn, the conversation-mixnet
sibling fork of Vuvuzela, consumes the identities, key-wheel material,
and signed configs produced here. Any change crossing the
neverlur/gjallarhorn boundary — onion format, signature scheme, edTLS,
signed-config schema, key-wheel epoch derivation — lands as **paired
pull requests** referencing each other. Module paths are stable:
`github.com/oluies/neverlur` and `github.com/oluies/gjallarhorn`.
Versioned `SignedConfig.Version` and `Inner.Version` fields enable
one-coordinator-at-a-time upgrades; mixed-version config chains within
a single dialing round are forbidden.

## Quality Gates

- `gofmt -l .` must be silent.
- `go vet ./...` must pass.
- `go test ./...` must pass, including the addfriend, dialing, pkg, and
  keywheel packages.
- Crypto PRs require KAT test additions; review must explicitly confirm
  KATs were checked against an authoritative source.
- Wire-format changes (signed-config schema, friend-request blob layout,
  key-wheel epoch encoding) require a `docs/` design note describing
  the format before code review begins.
- No commit may skip pre-commit hooks or signing (`--no-verify`,
  `--no-gpg-sign`). Hook failures are fixed at the root, not bypassed.

## Governance

This constitution supersedes ad-hoc convention. Amendments require a
commit that:

1. Edits this file with the new principle or revision.
2. Explains in the commit body why the change is necessary, what
   alternatives were considered, and what migration (if any) existing
   code requires.
3. Updates the version and amendment date below.

All PR reviews must check the change against these principles. A reviewer
who approves a PR that violates the constitution shares responsibility
for the violation. Complexity beyond what these principles require must
be justified inline in the PR description.

For day-to-day development guidance (commands, conventions, file layout),
see `CLAUDE.md` and the gjallarhorn `docs/PQ-MIGRATION.md` cross-system
roadmap.

**Version**: 1.0.0 | **Ratified**: 2026-05-22 | **Last Amended**: 2026-05-22
