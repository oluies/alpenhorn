---

description: "Task list for 001-pq-hybrid-crypto"
---

# Tasks: Post-Quantum Hybrid Cryptography

**Input**: Design documents in `specs/001-pq-hybrid-crypto/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: REQUIRED. The Neverlur constitution mandates KAT tests for every primitive integration (Quality Gate "Crypto PRs require KAT test additions") and the spec defines explicit half-compromise and cutover tests. Test tasks are first-class, not optional.

**Organization**: Tasks are grouped by user story. The two P1 stories (US1 hybrid KEM, US2 hybrid signatures) can proceed in parallel once the foundational PQ packages exist.

## Format: `[ID] [P?] [Story?] Description with file path`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 / US4 — maps to spec.md user stories
- All paths are repository-root-relative

## Path Conventions

This is a single Go module at the repository root. Test files live next to source files (`*_test.go`). New packages are top-level directories (`pqsig/`, `pqkem/`, `hybrid/`). No `src/` or `tests/` indirection.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add the CIRCL dependency, pin its version, refresh `NOTICE` per constitution Principle I, and capture the pre-migration performance baseline that gates SC-007.

- [X] T001 Add `github.com/cloudflare/circl v1.7.0` to `go.mod` via `go get github.com/cloudflare/circl@v1.7.0`, then `go mod tidy` to refresh `go.sum`
- [X] T002 Update `NOTICE` to list `github.com/cloudflare/circl` with its BSD-3-Clause attribution (constitution Principle I — every new third-party dependency listed)
- [X] T003 [P] Create `benchmarks/baseline-pre-pq.txt` by running existing benchmarks on `master`, then committing the captured numbers (one-shot reference for the 1.25× gate)
- [X] T004 [P] Create top-level package directories `pqsig/`, `pqkem/`, `hybrid/` and `docs/` with minimal `doc.go` package comments referring back to `specs/001-pq-hybrid-crypto/`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The three PQ primitive packages plus the wire-format struct skeletons that every user story depends on. **Nothing in Phase 3+ may start until this phase is green** (KAT tests passing).

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### PQ KEM package (`pqkem/`)

- [X] T005 [P] Implement `pqkem/pqkem.go` exposing `GenerateKey`, `Encapsulate`, `Decapsulate`, `EncapsulateDeterministic` wrappers around `github.com/cloudflare/circl/kem/mlkem/mlkem768` per `contracts/kat-mlkem768.md`
- [X] T006 [P] Commit FIPS 203 test vectors to `pqkem/testdata/fips203-vectors.json` from the NIST ACVP-Server reference output; record source URL + SHA-256 in the commit message
- [X] T007 Implement `pqkem/kat_test.go` covering the four KAT cases from `contracts/kat-mlkem768.md` (deterministic keygen, deterministic encapsulation, decapsulation, implicit-rejection); MUST run before any user story uses the package

### PQ signature package (`pqsig/`)

- [X] T008 [P] Implement `pqsig/pqsig.go` exposing `GenerateKey`, `GenerateKeyFromSeed`, `Sign`, `Verify`, `DeriveFromEd25519Seed` wrappers around `github.com/cloudflare/circl/sign/mldsa/mldsa65` per `contracts/kat-mldsa65.md`
- [X] T009 [P] Commit FIPS 204 test vectors to `pqsig/testdata/fips204-vectors.json`; record source + SHA-256 in commit message
- [X] T010 [P] Commit R4 binding KAT fixture to `pqsig/testdata/binding-kat.json` (one chosen Ed25519 seed → expected ML-DSA-65 pub bytes)
- [X] T011 Implement `pqsig/kat_test.go` covering the three KAT cases plus `TestDeriveBindingStable`; MUST run before any user story uses the package

### Hybrid combiner package (`hybrid/`)

- [X] T012 [P] Implement `hybrid/combiner.go` with `CombineKEM`, `SignedMessage`, and the three `Context*` constants per `contracts/hybrid-combiner.md`
- [X] T013 [P] Commit combiner KAT fixture to `hybrid/testdata/combine-kat.json`
- [X] T014 Implement `hybrid/combiner_test.go` with `TestCombineKAT`, `TestSessionKeyResistsClassicalCompromise`, `TestSessionKeyResistsPQCompromise`, `TestContextSeparation` (directly satisfies SC-003 and SC-004)

### Shared hybrid-identity type

- [X] T015 Implement `hybrid/identity.go` defining `HybridIdentity` (E1) and `HybridIdentityPublic` types with constructors that enforce the R4 binding on every load
- [X] T016 Implement `hybrid/identity_file.go` for `IdentityFile` (E2): read/write of `.neverlur-id-v2` files including v1→v2 in-place upgrade per R9
- [X] T017 [P] Implement `hybrid/identity_test.go` with `TestLoadRejectsBadBinding`, `TestUpgradeV1FileInPlace`, `TestRefuseGroupReadable`

### Wire-format struct skeletons (used by both US1 and US2)

- [X] T018 Define `introductionV2` struct, `SizeIntro = 6695`, `MarshalBinary`, `UnmarshalBinary` in `intro.go` (replacing the v1 struct); leave `Sign` / `Verify` as TODO stubs that panic — US1 fills in KEM fields' producers/consumers, US2 fills in signature halves
- [X] T019 Define `HybridSignature` struct and JSON codec in `config/hybrid_signature.go` per `contracts/signed-config-v2.md`; leave `SignedConfig.Verify` updates to US2
- [X] T020 Update `addfriend/mixer.go` `SizeIntro` constant (228 → 6695) and recompute `SizeEncryptedIntro = SizeIntro + ibe.Overhead`
- [X] T021 [P] Add `ed25519` ↔ hybrid migration shim in `cmd/guardian/neverlur-guardian-keygen/main.go` that produces a `.neverlur-id-v2` file (calls into `hybrid/identity_file.go`) — used by every downstream binary's first-boot path

**Checkpoint**: Foundational complete. `go test ./pqsig/... ./pqkem/... ./hybrid/...` MUST be green. The two P1 user stories can now proceed in parallel.

---

## Phase 3: User Story 1 - Forward-secret messaging via hybrid KEM (Priority: P1) 🎯 MVP

**Goal**: Deliver the central confidentiality property. Friend-request handshake derives session keys from `hybrid.CombineKEM(X25519, ML-KEM-768)`. Keywheel seeds are hybrid-derived. An adversary later breaking either primitive family alone cannot decrypt recorded post-migration sessions.

**Independent Test**: Run `TestE2EHybridFriendRequest` (per `quickstart.md` §5) and confirm: (a) introduction on the wire is v2 with `MLKEMPublicKey` populated, (b) keywheel seed at both ends equals the combiner output, (c) revealing only X25519 or only ML-KEM private material does not reveal the keywheel seed.

### Tests for User Story 1 (write first; ensure failing)

- [ ] T022 [P] [US1] Write `addfriend_e2e_test.go` `TestE2EHybridFriendRequest` — full friend-request through in-process coordinator/PKG/mixer/CDN; asserts introduction v2 byte layout and keywheel seed equals independent combiner output
- [X] T023 [P] [US1] Write `keywheel/keywheel_test.go::TestKeywheelHybridSeed` — feeds a known `(ssX25519, ssMLKEM, transcript)` tuple through `hybrid.CombineKEM(ContextKeywheelSeed, …)` and asserts the wheel's `SessionKey` for round R is byte-stable across builds

### Implementation for User Story 1

- [X] T024 [US1] Extend `sentFriendRequest` in `friendrequest.go`: add `MLKEMPublicKey mlkem768.PublicKey` and `MLKEMPrivateKey mlkem768.PrivateKey` next to the existing `DHPublicKey`/`DHPrivateKey`; update easyjson tags
- [X] T025 [US1] Extend `IncomingFriendRequest` in `friendrequest.go`: add `MLKEMCiphertext []byte` carrying the recipient's encapsulation over the initiator's ML-KEM public key
- [X] T026 [US1] Replace `OutgoingFriendRequest.ExpectedKey ed25519.PublicKey` with `ExpectedIdentity *hybrid.HybridIdentityPublic` in `friendrequest.go`; update all call sites
- [ ] T027 [US1] In `addfriend.go::genIntro`, generate both X25519 (`box.GenerateKey`) and ML-KEM-768 (`pqkem.GenerateKey`) ephemeral pairs; write both public halves into `introductionV2`
- [ ] T028 [US1] In `addfriend.go::newFriend`, replace the `box.Precompute` call with: X25519 ECDH via `curve25519.X25519`, ML-KEM `Decapsulate`, then `hybrid.CombineKEM(ContextKeywheelSeed, transcript, ssX25519, ssMLKEM)`; feed the 32-byte result into `keywheel.Wheel.Put`
- [X] T029 [US1] Build the transcript helper `transcriptForKeywheelSeed(initiatorID, responderID, dialingRound, …) []byte` colocated in `addfriend.go` (single use; not yet promoted to a shared package)
- [X] T030 [US1] Update `keywheel/keywheel.go` doc comment to state that the input secret to `Put` MUST come from `hybrid.CombineKEM` post-migration; add a short `// Pre-condition:` comment above `Put`
- [ ] T031 [US1] Regenerate `client_json.go` and `keywheel/keywheel_easyjson.go` (`go generate ./...`) to pick up new struct fields
- [ ] T032 [US1] Run `TestE2EHybridFriendRequest` and `TestKeywheelHybridSeed` — both MUST now pass

**Checkpoint**: US1 done. Two clients on the new build exchange a friend request whose session secret is hybrid-derived. Acceptance scenarios 1-3 of US1 satisfied.

---

## Phase 4: User Story 2 - Hybrid identity & configuration signatures (Priority: P1)

**Goal**: Every guardian-signed config, server identity certificate, and friend-introduction artifact carries both an Ed25519 and an ML-DSA-65 signature; verifiers require both.

**Independent Test**: Produce a v2 `SignedConfig` and a v2 `introductionV2`; verify both with the hybrid verifiers; strip the PQ half and confirm rejection; strip the Ed25519 half and confirm rejection. Stand up an `edtls.Listen` server and confirm a hybrid client establishes a session that fails if either cert extension is missing.

### Tests for User Story 2

- [ ] T033 [P] [US2] Write `config/config_test.go::TestVerifyV2Roundtrip`, `TestRejectStrippedPQSignature`, `TestRejectStrippedEdSignature`, `TestRejectMixedV1V2Chain` per `contracts/signed-config-v2.md`
- [ ] T034 [P] [US2] Write `intro_test.go` covering `TestSignVerifyRoundtrip`, `TestVerifyRejectsForgedClassicalSig`, `TestVerifyRejectsForgedPQSig`, `TestVerifyRejectsSubstitutedPQKey`, `TestUnmarshalRejectsWrongVersion` per `contracts/introduction-v2.md`
- [ ] T035 [P] [US2] Write `edtls/server_test.go` and `edtls/client_test.go` additions: `TestHybridHandshakeRoundtrip`, `TestRejectMissingPQExtension`, `TestRejectForgedPQSignature`, `TestRejectMismatchedPQKey` per `contracts/edtls-cert-v2.md`

### Implementation for User Story 2: signed configs

- [ ] T036 [US2] Bump `SignedConfigVersion` to 2 in `config/config.go`; add `MinClientVersion int` field, change `Signatures` to `map[string]hybrid.HybridSignature`
- [ ] T037 [US2] Extend `Guardian` in `config/config.go` with `PQKey mldsa65.PublicKey`; update `SignedConfig.Validate` to require both keys be of correct length
- [ ] T038 [US2] Rewrite `SignedConfig.Verify` and `VerifyConfigChain` in `config/config.go` to require both halves of every `HybridSignature` to validate via `pqsig.Verify` plus `ed25519.Verify`
- [ ] T039 [US2] Update `config/server.go` to require v2 records on write paths and emit `event=pq.downgrade` (with structured fields) when a v1 record is accepted before cutover
- [ ] T040 [US2] Regenerate `config/config_easyjson.go` (`go generate ./config`) for the new schema

### Implementation for User Story 2: introduction signatures

- [ ] T041 [US2] Implement `(*introductionV2).Sign` in `intro.go`: builds the `msg` per `contracts/introduction-v2.md`, signs with both halves of the supplied `*HybridIdentity`
- [ ] T042 [US2] Implement `(*introductionV2).Verify` in `intro.go`: verifies all three checks (Ed25519, ML-DSA-65, BLS multisig); returns `HybridVerifyError` distinguishing the failed half
- [ ] T043 [US2] Wire the new `LongTermKeyPQ` field through `addfriend.go::genIntro` (initiator) and the IBE-decode path (`addfriend.go::decodeAddFriendMessage`) so the recipient populates `IncomingFriendRequest.LongTermKey` and the PQ counterpart on the friendship record

### Implementation for User Story 2: edTLS cert v2

- [ ] T044 [US2] Implement `edtls/cert_v2.go` with marshal/unmarshal of the two critical X.509 extensions (`pqPublicKey`, `pqSignature`) per `contracts/edtls-cert-v2.md`; OID constants documented in `docs/wire-edtls-cert-v2.md`
- [ ] T045 [US2] Update `edtls/server.go::NewTLSServerConfig` to accept `*hybrid.HybridIdentity` and emit the new extensions inside `newSelfSignedCert`
- [ ] T046 [US2] Update `edtls/server.go::VerifyPeerCertificate` to require both extensions present, critical, and verifying
- [ ] T047 [US2] Update `edtls/client.go::NewTLSClientConfig`, `Dial`, `Client` to accept `*hybrid.HybridIdentity` / `*hybrid.HybridIdentityPublic`; verifier asserts `peer.EdPub == cert.PublicKey && peer.PQPub == extPub`
- [ ] T048 [US2] Add `edtls.NewTLSServerConfigLegacy(ed25519.PrivateKey)` shim that emits `event=pq.downgrade` on every accepted connection (transitional only; removed in the post-cutover release)
- [ ] T049 [US2] Run all three test files added in T033–T035 — all MUST pass

**Checkpoint**: US2 done. Combined with US1, both P1 stories are complete. SC-001 (100% hybrid sessions between updated peers) and SC-002 (100% hybrid signatures) are achievable for any pair of new↔new peers.

---

## Phase 5: User Story 3 - Migration without a flag day (Priority: P2)

**Goal**: Mixed-version peers coexist in a defined window. The cutover instant is operator-controlled and observable. After cutover, classical-only artifacts are rejected. Operators can produce a posture report in under 5 minutes (SC-005).

**Independent Test**: Stand up a 4-node testbed (2 on master, 2 on this branch). Confirm: new↔new uses hybrid; new↔old before cutover proceeds with `event=pq.downgrade` logged; new↔old after cutover is rejected with `event=pq.reject`. Run `neverlur-pq-posture report` and confirm output enumerates every classical-only peer.

### Tests for User Story 3

- [ ] T050 [P] [US3] Write `config/cutover_test.go::TestCutoverAcceptsV1Before` and `TestCutoverRejectsV1After` per `contracts/signed-config-v2.md`
- [ ] T051 [P] [US3] Write `edtls/cutover_test.go::TestRejectClassicalOnlyCertAfterCutover` per `contracts/edtls-cert-v2.md`
- [ ] T052 [P] [US3] Write `hybrid/identity_file_test.go::TestV1FileUpgradedOnFirstLoad` exercising the R9 upgrade-in-place path

### Implementation for User Story 3

- [ ] T053 [US3] Implement `hybrid/cutover.go` exposing `CutoverInstant() time.Time` (reads `NEVERLUR_PQ_CUTOVER` env at process start, caches; default = sentinel "never" if unset)
- [ ] T054 [US3] Wire `hybrid.CutoverInstant()` into `config/config.go::Verify` (downgrade-vs-reject branch) and `edtls/server.go` / `edtls/client.go` (verifier rejects classical-only after cutover)
- [ ] T055 [US3] Emit structured log events `event=pq.downgrade` (peer, artifact, reason) and `event=pq.reject` (peer, artifact, reason) at every downgrade/reject site
- [ ] T056 [P] [US3] Update every server binary key-load path to use `hybrid.LoadOrUpgradeIdentityFile`:
  - `cmd/guardian/neverlur-guardian-keygen/main.go`
  - `cmd/guardian/neverlur-guardian-sign-config/main.go`
  - `cmd/guardian/guardian.go`
  - `cmd/neverlur-coordinator/main.go`
  - `cmd/neverlur-mixer/main.go`
  - `cmd/neverlur-pkg/main.go`
  - `cmd/neverlur-cdn/main.go`
- [ ] T057 [US3] Implement `cmd/neverlur-pq-posture/main.go` with subcommands `identity`, `verify-config`, `report`; output is JSON and a tabular human view; reads a config chain and a snapshot of currently-known peers
- [ ] T058 [US3] Run T050, T051, T052 — all MUST pass

**Checkpoint**: US3 done. Acceptance scenarios 1-3 of US3 satisfied. The cutover is now operator-controlled and observable.

---

## Phase 6: User Story 4 - Identity-key rotation forward path (Priority: P3)

**Goal**: Operators can rotate a hybrid identity later, including (in a future release) dropping the classical half. The rotation event is signed by the outgoing key and accepted by clients.

**Independent Test**: Rotate a guardian identity, publish a new signed config under the rotated key, observe acceptance by hybrid clients and rejection of any new artifact signed by the revoked key.

### Implementation for User Story 4

- [ ] T059 [US4] Implement `hybrid/rotation.go` with `RotateIdentity(oldFile, newOutPath string) (*HybridIdentity, error)`: writes a fresh v2 file whose `rotated_from` field hashes the old identity
- [ ] T060 [US4] Add `cmd/guardian/neverlur-guardian-rotate/main.go` CLI: invokes `hybrid.RotateIdentity`, prints the resulting attestation that the operator must distribute
- [ ] T061 [US4] Extend `config/config.go` so a config that introduces a guardian whose `PrevIdentityHash` matches an outgoing guardian's hash is recognized as a rotation, not a guardian replacement; verifier requires the outgoing guardian to sign the rotation
- [ ] T062 [US4] Add `config/config_test.go::TestKeyRotationAccepted` and `TestRejectsArtifactSignedByRevokedKey`

**Checkpoint**: US4 done. Acceptance scenario 1 of US4 satisfied. Long-term forward-compatibility property established.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T063 [P] Write `docs/wire-signed-config-v2.md` (constitution Quality Gate: wire-format design notes required before code review begins)
- [ ] T064 [P] Write `docs/wire-introduction-v2.md`
- [ ] T065 [P] Write `docs/wire-edtls-cert-v2.md` (including the placeholder PEN OID and the tracking note for the production OID assignment)
- [ ] T066 [P] Add `benchmarks/` directory with `BenchmarkHybridFriendRequest`, `BenchmarkSignedConfigVerify`, `BenchmarkDialingRound10k`, `BenchmarkAddFriendRound10k`; wire CI to fail if any benchmark exceeds 1.25× `baseline-pre-pq.txt` (satisfies SC-007)
- [ ] T067 [P] Update top-level `README.md` to describe the hybrid posture, the cutover knob, and how to read `neverlur-pq-posture` output
- [ ] T068 [P] Update top-level `CLAUDE.md` already pointing to the plan; add a short note that crypto PRs must include the "threat-model impact" paragraph (constitution Principle II)
- [ ] T069 Run `gofmt -l .` and `go vet ./...`; both MUST be silent / green (constitution Quality Gates)
- [ ] T070 Run the full `quickstart.md` from top to bottom on a clean checkout; capture any deviation as a bug

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup)**: no dependencies
- **Phase 2 (Foundational)**: depends on Phase 1; BLOCKS Phases 3–6
- **Phase 3 (US1) and Phase 4 (US2)**: both depend on Phase 2; can proceed in parallel (different file sets — US1 owns `keywheel/`, `addfriend.go`, `friendrequest.go` KEM fields; US2 owns `config/`, `intro.go` sig halves, `edtls/`)
- **Phase 5 (US3)**: depends on Phases 3 AND 4 — the cutover mechanism needs the new wire formats to gate
- **Phase 6 (US4)**: depends on Phase 4 (signed-config v2 must exist before rotation can be encoded)
- **Phase 7 (Polish)**: depends on all desired user stories

### User-story dependencies summary

- US1 (P1): independent of US2 once Phase 2 is done. Delivers SC-003 / SC-004.
- US2 (P1): independent of US1 once Phase 2 is done. Delivers SC-001 / SC-002 (in combination with US1).
- US3 (P2): requires US1 and US2 (it gates the artifacts those produce). Delivers SC-005 / SC-006.
- US4 (P3): requires US2 (rotation rides on signed-config v2). No dependency on US1.

### Within each user story

- KAT and unit tests written first; MUST fail before implementation begins (constitution: "review must explicitly confirm KATs were checked against an authoritative source").
- Models / wire structs before services / handlers (already enforced by Phase 2 producing the struct skeletons).
- Story-internal integration test (`TestE2E…`) is the last task and MUST pass to close the phase.

### Parallel opportunities

- T003, T004 in Phase 1.
- T005/T006, T008/T009/T010, T012/T013, T017 in Phase 2 (different packages, same checkpoint).
- T022 and T023 in Phase 3.
- T033, T034, T035 in Phase 4.
- T050, T051, T052 in Phase 5.
- T056 spans 7 binary main files — each is independently editable [P]-style though tracked as a single task.
- All Phase 7 polish items.

---

## Parallel Example: Phase 2 Foundational

```bash
# Three primitive packages can land concurrently — different directories, no shared files:
Task: "Implement pqkem/pqkem.go per contracts/kat-mlkem768.md"
Task: "Implement pqsig/pqsig.go per contracts/kat-mldsa65.md"
Task: "Implement hybrid/combiner.go per contracts/hybrid-combiner.md"

# Their KAT fixture commits also land in parallel:
Task: "Commit pqkem/testdata/fips203-vectors.json"
Task: "Commit pqsig/testdata/fips204-vectors.json"
Task: "Commit hybrid/testdata/combine-kat.json"
```

## Parallel Example: US1 + US2 after Phase 2

```bash
# Two developers can take the two P1 stories simultaneously:
Developer A → Phase 3 (US1): keywheel hybrid seed + addfriend KEM path
Developer B → Phase 4 (US2): SignedConfig v2 + intro signatures + edTLS cert v2

# They re-converge at the Phase 5 cutover wiring.
```

---

## Implementation Strategy

### MVP First (US1 only)

1. Phase 1 Setup
2. Phase 2 Foundational — all KAT tests green
3. Phase 3 US1 — `TestE2EHybridFriendRequest` green
4. **STOP and VALIDATE**: a friendship established between two new-build peers has a hybrid-derived keywheel seed. SC-003 and SC-004 are demonstrable.
5. Decide whether to ship US1 alone (sessions hybrid, signatures still classical) or hold for US2

**Recommendation**: Do not ship US1 alone — without US2 the signature trust root is still classical, and a forged config from a quantum adversary could redirect users to a malicious mixer set. Ship US1+US2 together.

### Incremental delivery beyond MVP

1. Phases 1–2 → foundation ready
2. Phases 3 + 4 (US1 + US2) in parallel → hybrid messaging + hybrid signatures → first shippable release
3. Phase 5 (US3) → cutover-date enforcement, posture reporting → second release that includes the operator runway
4. Phase 6 (US4) → key rotation forward path → optional release; can defer
5. Phase 7 polish runs continuously alongside

### Parallel team strategy

- 1 dev: complete in order 1 → 2 → (3 → 4) → 5 → 6 → 7
- 2 devs after Phase 2: A on US1, B on US2; both join for US3
- 3 devs after Phase 2: A on US1, B on US2, C on US3 docs/posture-CLI scaffolding (deferring the parts of US3 that need US1/US2 to land first)

---

## Notes

- Every task is independently re-runnable; rerunning a completed task should be a no-op (idempotent `go generate`, KAT tests re-run, etc.).
- Commit at task boundaries; every commit message touching crypto/config/keywheel/addfriend MUST carry a "threat-model impact" paragraph per constitution Principle II.
- `go test ./...` MUST be green at every Checkpoint. CI runs the full suite plus the benchmark-budget check.
- Wire-format design notes (T063–T065) are pre-requisites for code-review approval per the constitution Quality Gate — file them before opening PRs that touch the corresponding wire format if reviewers haven't yet seen the design.
- Avoid: silently weakening the half-compromise test (SC-003/SC-004) by leaking the transcript into both branches; using `nacl/box.Precompute` anywhere in the new path; introducing a "PQ off for testing" build tag (constitution Principle III, NON-NEGOTIABLE).
