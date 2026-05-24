# Phase 0 Research: Conversation Wiring (Neverlur side, Phase A)

**Feature**: 002-conversation-wiring
**Date**: 2026-05-23

This document resolves every open technical question raised by the plan's Technical Context section. Each decision feeds directly into Phase 1 design.

---

## R1. Where does the conversation session key actually come from today?

**Finding**: Gjallarhorn's `cmd/gjallarhorn-client/conversation.go` already wires it through. The flow:

1. Alice calls `alpenhornClient.SendCall(bob, intent)` (Neverlur API; despite the local variable name, the package is the rebranded `neverlur`).
2. `SendCall` returns an `*OutgoingCall` whose `SessionKey()` reads from `keywheel.Wheel.SessionKey(bob, callRound)`.
3. Gjallarhorn's `GuiClient.SendingCall` hook receives the `OutgoingCall`, takes its `SessionKey()` and `Round()`, and uses them to seed a `keywheelStart` struct.
4. The `keywheelStart` is fed to a `Conversation` object; `Conversation.rollAndReplaceKey` ratchets the key forward per Gjallarhorn dialing round via SHA-512_256 chaining (`rollKey` in `conversation.go`).
5. `Conversation.Seal` and `Conversation.Open` use the rolled key with `nacl/secretbox` to encrypt/decrypt conversation packets.

**Decision**: Phase A does not change this flow. The session-key plumbing already exists and is already hybrid-derived (post-PR-#4) — because step 2's `keywheel.Wheel.SessionKey` returns whatever `Wheel.Put` was given as the seed, and post-PR-#4 that seed comes from `hybrid.CombineKEM(ContextKeywheelSeed, ...)`.

**Rationale**: Less code change = less risk of breaking the existing differential-privacy and mixnet anonymity properties of the Vuvuzela construction. The work is verification + integration tests + a demo binary, not protocol redesign.

**Alternatives considered**:
- Replacing the call-based bootstrap with a direct `wheel.SessionKey` lookup at conversation-start time: rejected because the existing call-based bootstrap encodes round agreement (the `roundSyncer` in `conversation.go`) that solves the "Alice and Bob need to agree on which round they're using" sub-problem. Reinventing that is out of scope.

---

## R2. What is the actual rebrand-incompleteness blocker in Gjallarhorn?

**Finding**: `cmd/gjallarhorn-client/alpenhorn.go` (12 sites, e.g. `func (gc *GuiClient) ConfirmedFriend(f *alpenhorn.Friend) {`) uses the identifier `alpenhorn.X` for types from the Neverlur package. The imports list shows only `"github.com/oluies/neverlur"` (no alias). The neverlur package's `package` directive is `package neverlur`, not `package alpenhorn`. Therefore the file as committed to Gjallarhorn master cannot compile against the rebranded module — the symbol `alpenhorn` is undefined.

The reason this hasn't surfaced as a build break: every developer trying to build this on arm64 hits the pre-existing bn256 assembly failure FIRST, which masks the rebrand-incompleteness error. On linux/amd64 CI it would also fail, but Gjallarhorn doesn't currently have CI configured.

**Decision**: The Gjallarhorn-side plan owns the fix. Either (a) rename `alpenhorn.X` → `neverlur.X` throughout the file (12 sites), or (b) add an import alias `alpenhorn "github.com/oluies/neverlur"`. Option (a) is the cleaner long-term answer; option (b) is the one-line patch.

**Recommended for the Gjallarhorn-side plan**: option (a). The file is small; the rebrand should be visible to readers.

**Rationale**: This is a Gjallarhorn-side problem but it surfaces from the Neverlur-side workspace setup, so Neverlur's plan calls it out as a Phase A prerequisite. The Phase A integration test on the Gjallarhorn side can't even compile until this is fixed.

---

## R3. What is the dead `replace` directive conflict in `go.work` mode?

**Finding**: Neverlur's go.mod contains `replace vuvuzela.io/alpenhorn => ./` (it's self-referential; the inherited Vuvuzela code imports `vuvuzela.io/alpenhorn` and the replace makes that resolve to neverlur itself). Gjallarhorn's go.mod contains `replace vuvuzela.io/alpenhorn => github.com/vuvuzela/alpenhorn v0.0.0-20190912152808-6b33518f681e` — a snapshot of the pre-rebrand Alpenhorn from upstream.

When both modules are in a Go workspace, `go build` errors with `conflicting replacements for vuvuzela.io/alpenhorn`. The Gjallarhorn-side replace is dead (nothing in Gjallarhorn currently imports `vuvuzela.io/alpenhorn`; the rebrand moved everything to `github.com/oluies/neverlur`). Removing it fixes the workspace.

**Decision**: The Gjallarhorn-side plan removes the dead `replace vuvuzela.io/alpenhorn => github.com/vuvuzela/alpenhorn ...` from Gjallarhorn's `go.mod`. Neverlur's replace stays (it's load-bearing for Neverlur's own build).

**Rationale**: The minimum change that unblocks the workspace. Neverlur's replace is in the Neverlur repo and not anyone else's concern; Gjallarhorn's replace is unused and removing it is risk-free.

---

## R4. Where should the integration test live?

**Decision**: The integration test lives in **Gjallarhorn**, at `gjallarhorn/e2e/first_message_test.go`. It imports both `github.com/oluies/neverlur` (for friend-discovery setup) and `github.com/oluies/gjallarhorn/convo` (for conversation packet construction).

**Rationale**:
- The test's failure modes are mostly about the Gjallarhorn conversation layer (round timing, mixnet harness setup, packet sealing/opening). Putting it in Gjallarhorn keeps the harness setup colocated with the code it harnesses.
- The Gjallarhorn-side CI will then run the test on every Gjallarhorn PR. Neverlur changes that break the contract will still fail Gjallarhorn's CI once Gjallarhorn pulls a new Neverlur version (post-`go get` and tag).
- A copy of the test could live in Neverlur for the same reason in reverse, but the maintenance cost of two parallel tests outweighs the benefit. One test, in Gjallarhorn.

**Alternatives considered**:
- Test in Neverlur: rejected because the bn256-dominated test build cost is already paid by Gjallarhorn (which transits bls), so moving the test there doesn't reduce build cost and adds a one-time dependency for Neverlur's CI to know about Gjallarhorn.
- Test in a third "e2e" module: rejected (overhead of a third module for one test).

---

## R5. How does the demo CLI stand up an in-process coordinator/mixer/CDN?

**Decision**: The demo CLI imports the same in-process harness that the integration test uses (R4). The harness lives in Gjallarhorn under `gjallarhorn/internal/testharness/` (or equivalent), exported for use both by the test and by the demo binary. The demo CLI in Neverlur (`cmd/neverlur-conversation-demo/inmemory.go`) is a thin wrapper that:

1. Starts the harness when the first instance launches (the "alice" terminal becomes the harness host).
2. The "bob" terminal connects to the same harness over a local Unix socket (the harness exposes a localhost-only typesocket endpoint).
3. Both terminals run their full client state machines against the shared harness.
4. On Ctrl-C in either terminal, both terminals shut down cleanly; the harness terminates last.

**Rationale**:
- Reusing the test harness means the demo and the test exercise exactly the same code path. The demo is "the test, but with stdin/stdout instead of test assertions" — which makes the demo's correctness story a corollary of the test's.
- The "first terminal hosts the harness" trick avoids a separate `neverlur-conversation-demo-server` binary. Two `demo` invocations are all the demonstrator runs.

**Alternatives considered**:
- Demo as a single multi-window terminal app (using a TUI framework): rejected as overkill for Phase A. The demo's purpose is "show the protocol works"; one process per peer is the simplest legible model.
- Separate server binary: rejected for the same reason. Less is more.

---

## R6. How does CI run a test that imports both repos?

**Decision**: The Gjallarhorn CI workflow (`.github/workflows/ci.yml` on Gjallarhorn) `go get`s the latest tagged Neverlur version and pins it via `go.mod` for the duration of the CI run. No workspace; CI uses standard module resolution. When a paired-PR-change-set is in review, the Gjallarhorn-side PR temporarily includes a `replace github.com/oluies/neverlur => github.com/oluies/neverlur@<commit-sha>` to test against the un-merged Neverlur PR; the replace is removed before merging the Gjallarhorn PR.

**Rationale**:
- Workspace is a per-developer local convenience; CI shouldn't depend on it (would require a non-portable directory layout).
- The temporary `replace` against a specific commit-sha is the established Go pattern for "this PR depends on an un-merged PR in another module."
- After both PRs merge, a normal `go get` updates Gjallarhorn's `go.mod` to the merged Neverlur version and the replace goes away.

**Alternatives considered**:
- Vendoring: rejected (large, painful for crypto code review).
- Submodule of Neverlur inside Gjallarhorn for CI: rejected (different mechanism than dev, surprising).

---

## R7. What's the minimum amount of new Neverlur code Phase A actually needs?

**Decision**: Roughly four files under `cmd/neverlur-conversation-demo/`:

- `main.go` — flag parsing (`-as alice`/`-as bob`, `-harness`), dispatch.
- `alice.go` — initiator path: register, send friend request, wait for confirm, send a typed message via the conversation layer.
- `bob.go` — responder path: register, approve incoming friend request, receive the message, print it.
- `inmemory.go` — thin wrapper around the Gjallarhorn-hosted harness (started/joined as appropriate).

Plus zero modifications to existing Neverlur protocol code.

**Rationale**: The hybrid keywheel seed path is already in place from `001-pq-hybrid-crypto`. The conversation session-key plumbing already exists in Gjallarhorn. Phase A's Neverlur contribution is purely the demo CLI; everything else lives in Gjallarhorn.

---

## R8. Hybrid carry-through verification — how is it tested?

**Decision**: The Gjallarhorn-side integration test (`e2e/first_message_test.go`) includes two subtests:

- `TestE2EFirstMessage_HybridConfidentiality_ClassicalCompromise`: after the round completes, the test inspects the seal-key chain and asserts that handing a hypothetical attacker only the X25519 component of the original friend-discovery shared secret does not let them derive the conversation session key. Implemented by extracting the per-round `secretbox` key, then attempting (in-test) to re-derive it from only the X25519 half via the same HKDF code path used by `hybrid.CombineKEMConcat`, asserting non-equality.
- `TestE2EFirstMessage_HybridConfidentiality_PQCompromise`: symmetric.

Plus a `TestNoClassicalSessionKeySource` static-check test (just a `grep` invocation via `os/exec` or a hand-written AST walk) that confirms no `box.Precompute` / `curve25519.X25519` / equivalent classical-only call site exists in the Gjallarhorn conversation path.

**Rationale**: The carry-through property is the constitutional reason for Phase A. Testing it directly closes the loop.

---

## R9. CI surface for Phase A

**Decision**:
- **Gjallarhorn CI** gains a new job step `Test (e2e)` that runs `go test ./e2e/...` on linux/amd64. The step is `continue-on-error: true` only until Phase A is fully landed; once landed it becomes a hard gate.
- **Neverlur CI** gains nothing new. The Phase A integration test is owned by Gjallarhorn; Neverlur's CI continues to run the foundational + boundary tests it already runs (and stays linux/amd64-restricted for the bn256-affected paths).

**Rationale**: One owner per test; the contract between the repos is enforced by the Gjallarhorn-side test, not by a duplicate Neverlur-side test.

---

## R10. Cutover-date instrumentation in Phase A

**Decision**: Phase A does NOT add cutover-date instrumentation. The spec assumption (and the Gjallarhorn-side assumption) is that US3 of `001-pq-hybrid-crypto` (the deferred cutover work) handles the operator-facing logging and posture reporting. Phase A's no-classical-fallback property is enforced *by absence of a fallback path*, not by a runtime warning.

**Rationale**: Bundling cutover plumbing into Phase A would inflate its scope and conflate two distinct constitutional concerns. Cutover instrumentation is a US3 deliverable; Phase A is US1 + US2 carry-through to conversation packets.

---

## Open items

None. All Technical Context unknowns are resolved.
