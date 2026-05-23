# Phase 1 Data Model: Conversation Wiring (Neverlur side, Phase A)

**Feature**: 002-conversation-wiring
**Date**: 2026-05-23

Phase A is largely a wiring + testing + demo exercise; very little new persistent or on-wire state is introduced. This document enumerates the entities the Neverlur side touches.

---

## E1. Demo CLI session (in-memory, per-process)

**Purpose**: Holds the state of one running `neverlur-conversation-demo` process — either "alice" or "bob". One per terminal.

**Fields**:
- `Role string` — `"alice"` or `"bob"`. Determines which prepared friend-discovery + conversation script the binary runs.
- `Username string` — the PKG-registered username (`"alice@demo.local"` or `"bob@demo.local"` by default; overridable via flag).
- `LongTermPrivateKey ed25519.PrivateKey` — generated at first launch and persisted to `$XDG_CACHE_HOME/neverlur-demo/<role>.id` for the life of the demo session, deleted on clean exit.
- `HybridIdentity *hybrid.HybridIdentity` — derived from `LongTermPrivateKey` via `hybrid.HybridIdentityFromEd25519Seed` at startup. Cached.
- `Client *neverlur.Client` — the standard Neverlur client state machine, fed the in-process harness's coordinator/PKG/CDN endpoints.
- `ConversationState *gjallarhorn.Conversation` — the Gjallarhorn-side conversation state machine, populated by the `SendingCall`/`ReceivedCall` callbacks.

**Lifecycle**:
- Created on `main()` after flag parsing.
- The "alice" instance also starts the in-process harness; the "bob" instance connects to it.
- Friend-discovery and first-message exchange run as scripted steps.
- On Ctrl-C: the conversation state is closed cleanly, the Neverlur client is closed, the harness is torn down (alice-only), the identity file is deleted.

**Validation**:
- Reject if `Role` is anything other than `"alice"` or `"bob"`.
- Reject if `Username` exceeds 64 bytes (the PKG identity-length limit).
- Reject if `LongTermPrivateKey` cannot be loaded or derived.

---

## E2. Demo message (user-typed payload)

**Purpose**: A single message the demonstrator types in their terminal to send to the peer.

**Fields**:
- `Body []byte` — the UTF-8 bytes the user typed, after stripping the trailing newline.
- `LengthBudget int` — the protocol's max message length (Gjallarhorn's `convo.ConvoMessageSize` constant). Set at compile time from the imported constant.

**Validation**:
- `len(Body) > 0` — empty messages are rejected at the input boundary with a user-readable error (`"empty message; type something to send"`).
- `len(Body) <= LengthBudget` — oversized messages are rejected with a user-readable error that quotes the actual budget (`"message too long: 421 bytes, max 256"`).
- `utf8.Valid(Body)` — non-UTF-8 input is rejected (defensive; terminal input is normally UTF-8 but we don't assume).

**Lifecycle**:
- Created from a single `bufio.Scanner.Scan()` call.
- Passed to `ConversationState.Seal(Body, round, sessionKey)` which produces the conversation packet for Gjallarhorn to ship.
- Receiver: extracted from `ConversationState.Open(ciphertext, round, sessionKey)` and printed verbatim to stdout with a `"<peer>: "` prefix.

---

## E3. Identity file on disk (demo-only, ephemeral)

**Purpose**: Persist the demo session's Ed25519 seed across hypothetical Ctrl-C-resume scenarios (the user kills alice and re-runs `demo -as alice` without restarting bob, and expects the same Alice identity to come back).

**Path**: `$XDG_CACHE_HOME/neverlur-demo/<role>.id` (default `~/.cache/neverlur-demo/alice.id`).

**Contents**: 32 bytes (raw Ed25519 seed). Mode 0600.

**Lifecycle**:
- Written on first launch of a role.
- Read on subsequent launches.
- Deleted on clean exit (`os.Remove`).
- **The file is EXPLICITLY documented in the demo's startup banner as ephemeral demo-only state**, NOT a production identity store. (Same plaintext-seed caveat as `.neverlur-id-v2` in `cmd/guardian/neverlur-guardian-keygen`'s `-hybrid-out` flag — see `docs/wire-introduction-v2.md` discussion.)

---

## E4. Demo harness (in-process Gjallarhorn coordinator + mixers + CDN)

**Purpose**: The in-memory mock of the Gjallarhorn service set, shared between the demo CLI's two terminals via a local Unix socket exposed by the alice-process. The same harness is what the integration test uses.

**Fields** (provided by Gjallarhorn-side `internal/testharness`):
- `Coordinator *coordinator.Server` (Gjallarhorn coordinator)
- `Mixers []*mixnet.MixServer` — three by default, to match the standard Vuvuzela 3-mixer setup
- `CDN *cdn.Server`
- `PKG *pkg.Server` — Neverlur-side, but instantiated in the harness because the demo's friend-discovery needs it
- `ListenAddr string` — local Unix-socket address (default `$XDG_RUNTIME_DIR/neverlur-demo.sock`)

**Lifecycle**:
- Started by the alice-process on first launch.
- Joined by the bob-process via the listen address.
- Torn down by the alice-process on its clean exit; the bob-process detects the connection drop and prints `"harness gone; exiting"`.

**Validation**:
- Refuse to start if the listen address is already occupied (another demo session in progress).

---

## Relationships

```
Demo CLI session (E1, per process) ──hosts/connects─> Demo harness (E4)
                                  ──holds────────> Hybrid identity (from neverlur/hybrid)
                                  ──drives───────> neverlur.Client
                                  ──drives───────> gjallarhorn.Conversation
                                                          ▲
Demo message (E2, per send) ──Seal/Open────────────────────┘

Identity file (E3) ──persists────> Hybrid identity (rederived on load)
```

---

## What this commit does NOT add

- No new persistent state in the Neverlur client itself. The demo session's persistence (E3) is a stand-alone demo-only file; the main Neverlur `Client` continues to use its existing `ClientPersistPath`/`KeywheelPersistPath` mechanism unchanged.
- No new wire-format structures. The conversation packet bytes Gjallarhorn produces and consumes are unchanged.
- No new client-state fields beyond what the existing friend-discovery + Gjallarhorn integration already requires.
