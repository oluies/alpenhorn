# Feature Specification: Conversation Wiring (Neverlur ↔ Gjallarhorn Phase A)

**Feature Branch**: `002-conversation-wiring`

**Created**: 2026-05-23

**Status**: Draft

**Input**: User description: "Phase A: wire Neverlur's hybrid keywheel seed into Gjallarhorn's conversation mixnet so two users who completed an Alpenhorn-style add-friend round can exchange their first real message; deliverables include a Go integration test that round-trips one message between two in-process clients and a neverlur-conversation-demo CLI that two terminals can drive interactively"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Friended pair exchanges a first message (Priority: P1)

Two users who have completed an Alpenhorn-style add-friend round through Neverlur (so each one's keywheel holds a per-friendship seed for the other) can each open the messaging app, write a message, send it, and see the peer's message arrive — across the Gjallarhorn conversation mixnet, without either party knowing that mixers, the coordinator, or other clients exist in between.

**Why this priority**: This is the foundational property of the whole system. Friend discovery without conversation is half a product. The full Vuvuzela/Alpenhorn protocol exists precisely so that *this* exchange — two users sending a real message under the metadata-private threat model — is the demonstrable outcome.

**Independent Test**: A single Go integration test stands up an in-process coordinator, mixer set, and CDN; runs two clients (Alice and Bob) through add-friend to establish a shared keywheel seed; then has Alice send "hello" and asserts Bob's receive handler observes "hello" in the next conversation round.

**Acceptance Scenarios**:

1. **Given** Alice and Bob have completed an add-friend round and each holds a keywheel seed for the other, **When** Alice's client sends a conversation message addressed to Bob during a Gjallarhorn dialing round, **Then** Bob's client receives the message intact during the same round and decrypts it under a session key derived from his keywheel.
2. **Given** the conversation message in transit, **When** the coordinator, the mixers, and any non-target client examine their inputs and outputs, **Then** none of them can determine that Alice and Bob are the pair conversing in this round (per the Vuvuzela threat model — the existing differential-privacy and mixing properties carry over unchanged).
3. **Given** the exchange completes, **When** the same pair attempts a second message in a later round, **Then** the second message uses a distinct per-round session key derived from the ratcheted keywheel, and the second message's compromise does not reveal the first (forward secrecy on the classical half, hybrid confidentiality on both halves).

---

### User Story 2 - Conversation confidentiality inherits the PQ hybrid property (Priority: P1)

The whole point of Neverlur's hybrid PQ migration (`specs/001-pq-hybrid-crypto/`) is that conversations remain confidential against a future quantum adversary who recorded today's traffic. That property holds at the friend-discovery layer once the wire-switch lands. This story extends the property to the conversation layer: the session key Gjallarhorn uses to encrypt a conversation packet must derive from the same hybrid keywheel seed (the output of `hybrid.CombineKEM(ContextKeywheelSeed, ...)`) that Neverlur produced.

**Why this priority**: P1 because shipping conversation wiring that silently uses a classical-only session-key derivation would be a Constitution Principle III violation (Hybrid, Never Pure — non-negotiable). The whole point of the foundation work is to carry the property forward; the conversation layer is where users actually feel it.

**Independent Test**: A test that simulates a "classical-half compromise" against a captured conversation packet (handing the test verifier only the X25519 shared secret from the original friend-discovery round) and asserts the verifier cannot derive the conversation per-round session key. Symmetric test for PQ-half compromise.

**Acceptance Scenarios**:

1. **Given** a conversation packet captured in transit, **When** an attacker recovers the classical (X25519) shared secret that was used during the originating friend-discovery round but does not recover the ML-KEM shared secret, **Then** the attacker cannot derive the conversation session key under which the packet was encrypted.
2. **Given** the symmetric scenario where the attacker recovers ML-KEM but not X25519, **When** they attempt to derive the conversation session key, **Then** they fail.
3. **Given** the keywheel ratchet has advanced beyond the round in which the message was sent, **When** an attacker later compromises the post-ratchet keywheel state, **Then** they cannot derive the pre-ratchet round's session key (forward secrecy preserved by the existing ratchet, unchanged by this work).

---

### User Story 3 - Developer can prove the round-trip works in CI (Priority: P2)

A developer working on Neverlur or Gjallarhorn can run a single Go integration test that exercises the full friend-discovery + first-conversation-message path with both repos in one process, and the test asserts the message round-trips successfully. The test runs in linux/amd64 CI (the bn256 arm64 limitation precludes local execution on Apple Silicon for the integration layer, but the result on CI is the load-bearing signal).

**Why this priority**: P2 rather than P1 because the integration test is the *evidence* that US1 works, not US1 itself. Without it, every change to either repo's protocol code risks silently breaking the end-to-end property; with it, regressions surface at PR-review time.

**Independent Test**: Run `go test -run TestE2EFirstMessage -timeout 5m ./...` on a checkout of both repos pinned to known-compatible commits. Exit status zero is the test passing.

**Acceptance Scenarios**:

1. **Given** a fresh CI environment with both repos at compatible commits, **When** the integration test runs, **Then** it completes within 5 minutes and asserts that Bob's receive handler observed Alice's sent bytes.
2. **Given** a regression in either repo's session-key derivation, **When** the integration test runs, **Then** the round-trip fails with a structured error that points at the disagreement (e.g. "Alice session key != Bob session key").

---

### User Story 4 - Demonstrator can run two terminals and watch a real message flow (Priority: P3)

A person showing the system to someone else (a colleague, a paper reviewer, a potential collaborator) can launch two terminals on one laptop, register two usernames, complete an add-friend round, and exchange one message — without writing test code. The demo is what makes the property *legible* to people who don't read Go test files.

**Why this priority**: P3 because the integration test (US3) is sufficient for *correctness* signal; the CLI is for *human comprehension*. Skipping the CLI doesn't break anything, but having it makes the system demonstrable.

**Independent Test**: Manual smoke test on one machine. Launch terminal A, register "alice", launch terminal B, register "bob", have alice send a friend request, have bob accept, watch alice's terminal print "you can now message bob", have alice type "hello", watch bob's terminal print "alice: hello".

**Acceptance Scenarios**:

1. **Given** a fresh laptop with no prior state, **When** the demonstrator runs the `neverlur-conversation-demo` binary in two terminals with appropriate flags, **Then** the friend-discovery round and the first conversation message both complete in under 5 minutes of wall-clock time including the user typing.
2. **Given** the demo is mid-conversation, **When** the demonstrator quits one terminal, **Then** the other terminal exits cleanly without leaving orphaned mixer processes or temp files.

---

### Edge Cases

- **One peer never joins the conversation round**: Alice composes a message but Bob's client is offline. The round completes; Alice's message is queued in Gjallarhorn's mailbox according to the existing protocol; the round-trip test marks this case as a non-failure (the system's behavior matches Vuvuzela's existing semantics — the message is delivered when Bob next connects).
- **Mixer collusion**: If all mixers in the round are colluding, the anonymity property degrades to the multi-server property of the Vuvuzela paper; the existing threat model and tests cover this and Phase A does not change it.
- **Mid-conversation keywheel ratchet**: The keywheel ratchets per dialing round; if Alice and Bob exchange messages across a ratchet boundary, the per-round session keys differ between the two messages but both still derive correctly from the wheel.
- **Friend exists in Neverlur but not in Gjallarhorn's view**: The integration must ensure that a wheel populated by Neverlur's `newFriend` path is visible to the conversation-layer code in Gjallarhorn through a single shared interface — there is no "Neverlur wheel" and "Gjallarhorn wheel" allowed to drift.
- **CLI sends an empty message or a message larger than the conversation round's per-packet size limit**: The CLI must validate at the input boundary; the protocol's max-message-size constant is enforced; oversized input is rejected with a user-readable error.

## Requirements *(mandatory)*

### Functional Requirements

#### Boundary between Neverlur and Gjallarhorn

- **FR-001**: Gjallarhorn MUST consume the keywheel seed produced by Neverlur's `keywheel.Wheel` such that for any `(username, dialingRound)` pair, both peers derive the same conversation session key from `Wheel.SessionKey(username, dialingRound)`.
- **FR-002**: The wheel object MUST be a single shared instance (or equivalent shared persistence) between the Neverlur friend-discovery path and the Gjallarhorn conversation path. Two separate wheels with copied state are forbidden; ratcheting MUST happen exactly once per round across the whole client.
- **FR-003**: The integration interface between Neverlur and Gjallarhorn MUST be defined in a single Go package whose import path is stable and version-pinned across both module manifests, so a coordinated upgrade is mechanical.

#### Conversation round-trip

- **FR-004**: A client that holds a keywheel seed for a friend `Bob` MUST be able to address a conversation packet to Bob's mailbox derived from `Wheel.OutgoingDialToken(bob, round, intent)` for the dialing round in scope.
- **FR-005**: A client that receives a mailbox containing packets MUST be able to decrypt the packet addressed to it using the session key derived from `Wheel.SessionKey(friend, round)` for the matching `(friend, round)` pair.
- **FR-006**: Conversation packets MUST carry enough information for the receiver to know which friend's session key to use, without the mixers, coordinator, or non-target clients learning the same.

#### Hybrid PQ confidentiality carry-through

- **FR-007**: The conversation session key MUST derive from the keywheel state produced by `hybrid.CombineKEM(ContextKeywheelSeed, ...)` whenever the friendship was established post-cutover. No code path in Gjallarhorn MAY derive a conversation session key from raw classical material that bypasses the hybrid combiner.
- **FR-008**: An adversary who recovers only the classical (X25519) component of the original friend-discovery shared secret MUST NOT be able to derive the conversation session key (the hybrid combiner property carries through).
- **FR-009**: An adversary who recovers only the post-quantum (ML-KEM) component MUST symmetrically fail.

#### Integration test

- **FR-010**: The repository MUST contain a Go integration test that, in a single test process, stands up an in-process Gjallarhorn coordinator, mixer set, and CDN; runs two Neverlur clients (Alice and Bob) through add-friend; sends one conversation packet from Alice to Bob; and asserts Bob received Alice's bytes intact.
- **FR-011**: The integration test MUST run within 5 minutes wall-clock on linux/amd64 CI runners; it MAY skip on arm64 due to the pre-existing bn256 limitation, with a clear skip message.
- **FR-012**: The integration test MUST fail loudly with a diagnostic that names the disagreement (Alice's session key vs Bob's session key, or any other point of divergence) when the round-trip property is broken by a regression in either repo.

#### Demo CLI

- **FR-013**: The repository MUST ship a binary at `cmd/neverlur-conversation-demo/` that two terminals on one laptop can launch to exercise the full friend-discovery and first-conversation-message journey interactively.
- **FR-014**: The demo binary MUST validate user-typed messages at the input boundary (length, encoding) before submitting them to the conversation layer; oversized messages MUST be rejected with a user-readable error that names the protocol's per-packet size limit.
- **FR-015**: The demo binary MUST exit cleanly when interrupted (Ctrl-C), leaving no orphaned mixer subprocesses or temp directories.
- **FR-016**: The demo binary's source code MUST NOT serve as a model for production usage; the file header MUST state explicitly that this is demo-only software intended for showing the protocol shape, not for handling real user messaging.

### Key Entities *(include if feature involves data)*

- **Per-Round Conversation Session Key**: The 32-byte key under which a single conversation packet between Alice and Bob in dialing round R is encrypted. Derived from `keywheel.Wheel.SessionKey(peer, R)` and ultimately from the hybrid combiner output captured at the friend-discovery moment.
- **Conversation Packet**: The fixed-width payload Gjallarhorn carries through its mixnet rounds. Existing Vuvuzela construction; Phase A does not change its on-wire format.
- **Shared Client State**: A single in-process object that hosts both the Neverlur friend-discovery state machine and the Gjallarhorn conversation state machine, exposing a single `wheel` member to both. Used by the CLI demo and by the integration test.
- **Demo Round**: A scripted sequence of `(register Alice, register Bob, Alice sends friend request, Bob approves, Alice sends "hello", Bob sees "hello")` exercised by both the integration test and the CLI demo against the same in-process backend.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A green CI run of the new integration test demonstrates that one message round-trips between two friended in-process clients in under 5 minutes wall-clock on a Linux/amd64 runner.
- **SC-002**: The "classical-half compromise" test in the integration suite confirms that an adversary holding only the X25519 component of the original friend-discovery shared secret cannot derive the conversation session key.
- **SC-003**: The symmetric "PQ-half compromise" test confirms the same property for the ML-KEM half.
- **SC-004**: Two terminals on one fresh laptop can complete the full demo journey (register → add-friend → first message) in under 5 minutes, including human typing time, without any orphaned subprocesses or temp directories left after exit.
- **SC-005**: Neither Neverlur nor Gjallarhorn ships a code path that produces or consumes a conversation session key derived from raw classical material; static analysis (a `staticcheck` or simple grep) finds zero occurrences of "session key from non-hybrid source" patterns.
- **SC-006**: A regression in either repo's session-key derivation (introduced intentionally in a test) causes the integration test to fail with a diagnostic that names the disagreement within 10 seconds of the regression.

## Assumptions

- **Gjallarhorn parity is the prerequisite**: This spec assumes Gjallarhorn's `task/newpq-fdae3f` (rebrand + spec-kit, now merged to Gjallarhorn master) is the baseline. Phase A does not re-do that work.
- **Conversation cryptography is Vuvuzela's existing construction**: Phase A wires the keywheel seed in; it does NOT redesign the conversation packet format, the dialing-round protocol, or the dead-drop convention. Those remain as documented in the Vuvuzela paper and as implemented in the inherited `vuvuzela.io/vuvuzela` code now under `gjallarhorn/`.
- **PKG attestation v2 is NOT a prerequisite**: This Phase A spec deliberately operates against the existing classical PKG attestation chain (the `pkg.Attestation` struct as it stands today). The PKG attestation v2 design note (`docs/wire-pkg-attestation-v2.md`) flags the gap; closing that gap is its own sub-project. Phase A's threat-model statement explicitly notes the residual PKG attestation surface as a known limitation.
- **The addfriend wire switch is NOT a prerequisite**: Phase A can be demonstrated using the in-memory hybrid keywheel seed pathway that already works (per the `keywheel_hybrid_test.go` and `keywheel_seed_test.go` files). The on-wire `introductionV2` format is deferred to its own commit; Phase A's integration test uses the helper-level path.
- **Constitutional boundary handling**: Per the Compatibility section, every code change crossing the Neverlur ↔ Gjallarhorn boundary lands as paired PRs. Phase A's deliverables span both repos; this spec is the Neverlur-side primary spec, and a companion Gjallarhorn spec will be drafted next (assumed to live at `gjallarhorn/specs/001-conversation-wiring/spec.md` or similar).
- **CLI demo is demo-quality, not production-quality**: It is intended for showing the protocol works end-to-end. Production messaging UX is Phase B (the Flutter app) and is out of scope here.
- **Per-deployment cutover instrumentation is Phase C**: The structured `event=pq.downgrade` / `event=pq.reject` logs and the operator-side `neverlur-pq-posture` CLI are Phase C's deliverables; Phase A's integration test asserts the no-downgrade property directly (no fallback path exists in the new code), not via instrumentation.
