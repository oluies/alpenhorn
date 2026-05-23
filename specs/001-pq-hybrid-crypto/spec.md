# Feature Specification: Post-Quantum Hybrid Cryptography

**Feature Branch**: `001-pq-hybrid-crypto`

**Created**: 2026-05-22

**Status**: Draft

**Input**: User description: "move to pq encryption use european implementation if exist — Hybrid X25519+ML-KEM, Ed25519+ML-DSA"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Forward-secret messaging that survives a future quantum adversary (Priority: P1)

A privacy-conscious user exchanges friend requests, dialing tokens, and conversation traffic over Neverlur today. A network adversary records all of that traffic and stores it. Years later the adversary gains access to a cryptographically relevant quantum computer and attempts to decrypt the archive ("harvest now, decrypt later"). The user's past traffic must remain confidential.

**Why this priority**: This is the central reason for the migration. Every other story is in service of it. Without hybrid post-quantum confidentiality at the messaging layer, the whole product's privacy guarantee degrades the day a quantum computer arrives.

**Independent Test**: Encrypt a payload with the new hybrid KEM, capture the ciphertext, simulate a "classical break" by revealing the classical (X25519) shared secret, and confirm the plaintext is still unrecoverable because the PQ component is still secret. Repeat with the PQ secret revealed and the classical secret intact — plaintext still unrecoverable. Either component alone must be insufficient.

**Acceptance Scenarios**:

1. **Given** two clients running the new version, **When** they exchange a friend request and subsequent dialing/conversation traffic, **Then** session keys are derived from a combiner over both the classical (X25519) and the post-quantum (ML-KEM) shared secrets such that compromise of either family alone does not reveal the session key.
2. **Given** a passive recording of a session, **When** an attacker later obtains the classical private key but no PQ key, **Then** they cannot decrypt the session.
3. **Given** a passive recording of a session, **When** an attacker later defeats the PQ KEM but the classical key is intact, **Then** they still cannot decrypt the session.

---

### User Story 2 - Tamper-evident system configuration and identity signatures (Priority: P1)

Guardians sign the global Neverlur configuration (mixer set, PKG set, CDN set, etc.). Servers sign their own identity certificates. Clients sign friend introductions. A future quantum attacker who can forge classical (Ed25519) signatures must still be unable to forge configurations, certificates, or introductions accepted by current clients.

**Why this priority**: Signature forgery on the system configuration breaks the trust root of the entire network. This is at the same criticality as message confidentiality and must ship in the same release wave.

**Independent Test**: Generate a config signed under the new hybrid signature scheme, present it to a verifier with the classical half stripped or replaced with a forgery, and confirm rejection. Likewise strip/forge the PQ half and confirm rejection. Both components must verify.

**Acceptance Scenarios**:

1. **Given** a guardian-signed configuration produced by the new version, **When** a client verifies it, **Then** the client requires both the classical (Ed25519) and the post-quantum (ML-DSA) signature to verify before accepting the configuration.
2. **Given** a server identity certificate produced by the new version, **When** a client establishes a session, **Then** verification of the server identity requires both signature components to validate.
3. **Given** a friend introduction produced by the new version, **When** the recipient verifies it, **Then** both signature components must validate before the introduction is accepted.

---

### User Story 3 - Existing deployments and clients migrate without a flag day (Priority: P2)

The operator of a running Neverlur deployment and the users connected to it cannot all upgrade at the same instant. There must be a defined transition window in which old and new versions coexist, with a published cut-over after which only hybrid PQ traffic is accepted.

**Why this priority**: Without a transition story the migration is theoretical. P2 rather than P1 because the privacy guarantee in Story 1 is what creates the urgency; the transition mechanism only has to be ready by the time real users are on the new build.

**Independent Test**: Run a mixed-version testbed (some servers and clients on the old version, some on the new) and confirm that (a) new↔new sessions use hybrid PQ, (b) the system has a documented and observable mechanism to refuse non-hybrid sessions once the cut-over date passes, and (c) operators have a clear signal that any classical-only peer still in the network is non-compliant.

**Acceptance Scenarios**:

1. **Given** a new client and a new server, **When** they negotiate, **Then** the session uses hybrid PQ for both KEM and signatures.
2. **Given** the configured cut-over date has passed, **When** any peer attempts a classical-only handshake or presents a classical-only signed artifact, **Then** the verifier rejects it.
3. **Given** a system operator, **When** they inspect a running deployment, **Then** they can determine which peers, configs, and certificates are still classical-only.

---

### User Story 4 - Operators can rotate identity keys to PQ-only later (Priority: P3)

Long after the migration completes, the project may wish to retire the classical halves of identity keys (e.g., because the classical component is later found to be the weak link). The system must allow guardians, mixers, PKG servers, and CDN operators to roll their identity keys, and clients must be able to accept the rolled keys, without re-bootstrapping the network.

**Why this priority**: Important for long-term hygiene but not required at first ship. The hybrid construction protects against the immediate threat; the ability to later drop the classical half is a forward-compatibility property.

**Independent Test**: Generate a new identity keypair (still hybrid for now, but with a different classical key), publish a signed key-rotation event under the old key, and confirm clients accept traffic signed under the new key while rejecting traffic signed under the revoked old key.

**Acceptance Scenarios**:

1. **Given** a guardian whose key has been rotated, **When** they sign a new configuration, **Then** clients honoring the rotation accept the new signature and reject any new signature under the old key.

---

### Edge Cases

- **Mixed-version peers during the transition window**: A new client encounters a server that only offers the classical handshake. Before the cut-over date, the client may proceed with a clearly logged downgrade; after the cut-over date, the client must refuse.
- **Partial PQ failure**: An implementation bug, malformed PQ key, or oversized PQ artifact causes one component of the hybrid construction to fail. The system must reject the session/signature outright rather than silently fall back to the classical half.
- **Stored ciphertext from old versions**: Messages and mailbox payloads created under the pre-migration classical-only scheme remain readable by their intended recipients (data-at-rest is out of scope to re-encrypt), but the migration does not retroactively claim PQ confidentiality for them.
- **Artifact size growth**: PQ public keys, ciphertexts, and signatures are substantially larger than their classical counterparts. Mixer rounds, dialing rounds, and bandwidth-bounded transports must remain functional under the new artifact sizes within a defined budget.
- **Replay across versions**: An attacker captures a classical-only signed config from before the cut-over and replays it after. The verifier must reject it after the cut-over date.
- **Key-material storage on disk**: Existing on-disk key files contain only the classical key. The upgrade must generate the PQ counterpart and persist it alongside, or migrate to a new combined format, without losing the existing classical key or its existing identity.

## Requirements *(mandatory)*

### Functional Requirements

#### Hybrid key encapsulation (KEM)

- **FR-001**: The system MUST establish session keys using a hybrid construction that combines an X25519 ECDH shared secret with an ML-KEM-derived shared secret, such that the resulting session key is at least as strong as the stronger of the two components.
- **FR-002**: The combiner MUST be IND-CCA-secure in the hybrid sense: an adversary who learns one component (X25519 or ML-KEM) but not the other MUST NOT be able to derive the session key.
- **FR-003**: The system MUST NOT permit a session to negotiate "classical-only" or "PQ-only" once the cut-over date has passed. Before the cut-over date, downgrade to classical-only MAY be permitted but MUST be logged and observable to operators.

#### Hybrid signatures

- **FR-004**: The system MUST produce signatures over guardian-signed configurations, server identity certificates, and client friend-introduction artifacts as a hybrid of Ed25519 and ML-DSA, such that verifiers require both components to validate.
- **FR-005**: A signature in which either the classical or the post-quantum component is missing, malformed, or invalid MUST be rejected after the cut-over date.

#### Identity and key material

- **FR-006**: Guardian, mixer, PKG, CDN, and client identity key material MUST be representable as a hybrid pair (classical + post-quantum). The two halves MUST be bound together at generation time so they cannot be substituted independently in stored or transmitted identities.
- **FR-007**: Upgrading an existing deployment MUST preserve the existing classical identity of each principal (so that prior signatures and trust relationships remain valid for backward verification) and add the post-quantum counterpart alongside it.
- **FR-008**: Key generation, signing, verification, encapsulation, and decapsulation operations MUST be constant-time with respect to secret material to the extent the underlying primitives permit.

#### Protocol surfaces affected

- **FR-009**: The friend-request, friend-introduction, dialing, and add-friend flows MUST use the hybrid KEM for any operation that today derives a session key or wraps a per-conversation key.
- **FR-010**: The transport-layer identity binding currently provided by edtls (server identity tied to TLS handshake) MUST be extended so that the server's identity assertion is verifiable as a hybrid signature.
- **FR-011**: Guardian configuration signing and verification MUST be hybrid. The configuration format MUST carry the post-quantum signature alongside the existing classical signature in a way that an old verifier sees a well-formed (classical) signature and a new verifier sees both.
- **FR-012**: The keywheel and any other long-lived per-relationship key material derived from a session MUST be derived from the hybrid combined secret, not from the classical half alone.

#### Transition and observability

- **FR-013**: The system MUST expose, to operators, the hybrid-PQ posture of every connected peer, signed configuration, and server certificate currently in use — at minimum: "hybrid", "classical-only", or "unverifiable".
- **FR-014**: The system MUST publish and honor a cut-over date, after which classical-only artifacts are rejected. The cut-over date MUST be settable per deployment and visible in the configuration.
- **FR-015**: When a downgrade or rejection occurs, the system MUST emit a structured event identifying the peer, the artifact, and the reason, so that operators can investigate before/after the cut-over.

#### Implementation provenance

- **FR-016**: The chosen PQ primitive implementations MUST be actively maintained, publicly reviewed, and pass the standardized test vectors for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). The specific library/SDK choice is a planning-phase decision (see Assumptions).

### Key Entities *(include if feature involves data)*

- **Hybrid Identity Key**: A pair consisting of one classical (Ed25519) keypair and one post-quantum (ML-DSA) keypair, bound together as a single identity. Used by guardians, mixers, PKG servers, CDN servers, and clients to sign artifacts attributable to that identity.
- **Hybrid KEM Keypair**: A pair consisting of one classical (X25519) keypair and one post-quantum (ML-KEM) keypair, used to derive session keys during friend-request, dialing, and conversation establishment.
- **Hybrid Signature Artifact**: A signed object (configuration, certificate, introduction) carrying both a classical signature and a post-quantum signature over the same canonical message, verifiable as a unit.
- **Hybrid Session Secret**: The output of combining an X25519 shared secret and an ML-KEM shared secret through a key combiner; the input to all subsequent symmetric key derivation.
- **PQ Migration Posture**: A per-peer, per-artifact attribute observable by operators, describing whether that peer/artifact is hybrid, classical-only, or unverifiable, used during the transition window.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After the cut-over date, 100% of newly established sessions between up-to-date peers derive their session key from a hybrid combiner over both a classical and a post-quantum shared secret. Zero sessions accept a classical-only key exchange.
- **SC-002**: After the cut-over date, 100% of newly published guardian configurations, server identity certificates, and friend introductions carry both a classical and a post-quantum signature, and verifiers reject any artifact missing either.
- **SC-003**: An adversary who possesses a complete recording of post-migration traffic and is later given the long-term classical private keys of both endpoints CANNOT recover plaintext from any post-migration session (validated by an explicit test suite that simulates classical-half compromise).
- **SC-004**: An adversary who possesses a complete recording of post-migration traffic and is later given the long-term post-quantum private keys of both endpoints CANNOT recover plaintext from any post-migration session (validated by an explicit test suite that simulates PQ-half compromise).
- **SC-005**: During the transition window, operators can produce, in under 5 minutes, a report listing every peer/artifact in their deployment that is still classical-only.
- **SC-006**: Migration of an existing deployment (existing guardians, mixers, PKG, CDN, and at least one prior signed configuration) to the hybrid scheme completes without invalidating prior signed artifacts that the deployment chooses to keep honoring during the transition window.
- **SC-007**: A round of dialing, a round of add-friend mixing, and a friend-request exchange each complete under the hybrid scheme within a per-deployment latency budget that is no worse than 1.25× the pre-migration latency for the same round size. If a candidate design cannot meet this ceiling at the default parameter sets (ML-KEM-768, ML-DSA-65), the planning phase must either justify a smaller parameter set, identify the bottleneck (CPU, bandwidth, batch coordination), or document the slip with operator sign-off before shipping.

## Assumptions

- **Algorithm choice is fixed by the user**: X25519+ML-KEM for hybrid KEM and Ed25519+ML-DSA for hybrid signatures are the chosen algorithm families. This spec does not reopen the choice; it specifies the system properties those choices must produce. Parameter set selection within ML-KEM (512/768/1024) and ML-DSA (44/65/87) is a planning-phase decision, with ML-KEM-768 and ML-DSA-65 assumed as the default unless the plan justifies otherwise.
- **Standards baseline**: The post-quantum primitives are taken to be the NIST-standardized ML-KEM (FIPS 203) and ML-DSA (FIPS 204). Pre-standard or competing variants (e.g. Kyber as named in the round-3 spec, Dilithium pre-standardization) are not in scope; if only such variants are available in a chosen library, the planning phase must call that out.
- **Threat model is "harvest now, decrypt later"**: The primary adversary is one who records traffic now and gains quantum capability later. Adversaries who already have quantum capability today are out of scope (this matches the public state of the field as of 2026-05).
- **Transition window exists and is bounded**: The deployment operator sets and publishes a cut-over date. There is no plan to support classical-only peers indefinitely.
- **Existing classical keys remain valid as the classical half**: Upgrading does not require regenerating existing Ed25519 identities. The PQ half is generated and bound to the existing classical identity.
- **Data-at-rest is out of scope**: The existing on-disk encrypted state (Badger DB contents, persisted keywheel state, stored mailbox payloads) is not re-encrypted by this migration. Future messages and future session keys are PQ-protected; historical at-rest data inherits whatever protection it had.
- **TLS-to-the-coordinator is out of scope**: Standard HTTPS endpoints from clients to coordinator/CDN HTTP services rely on whatever the surrounding TLS stack provides. This spec addresses the application-layer cryptography (KEM, signatures, identity binding) inside the Neverlur protocols, not the underlying public-Internet TLS.
- **PQ library choice — Cloudflare CIRCL**: The planning phase will use Cloudflare CIRCL as the source for ML-KEM and ML-DSA. CIRCL is a publicly developed, audited, and actively maintained Go cryptography library with conformant implementations of the FIPS 203 / FIPS 204 standards. This choice supersedes any earlier "European implementation preferred" framing and is recorded here so that the spec stays library-agnostic while the planning artifacts can reference it directly.
