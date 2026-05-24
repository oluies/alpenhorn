# Contract: End-to-End Test Harness

**Owner**: Gjallarhorn (hosts the harness); Neverlur (consumes it from the demo CLI)
**Stability**: harness API is stable from this Phase A commit; changes require both repos to update in lockstep.

## What the harness provides

A Gjallarhorn-side Go package (proposed: `github.com/oluies/gjallarhorn/internal/testharness`, but exported via a friendly path so the demo CLI can import it too) exposes:

```go
package testharness

// Harness is an in-memory stand-up of the full Gjallarhorn service set
// plus the Neverlur-side PKG, suitable for both integration tests and
// the demo CLI.
type Harness struct {
    Coordinator     *coordinator.Server
    Mixers          []*mixnet.MixServer  // 3 by default
    CDN             *cdn.Server
    PKG             *pkg.Server          // Neverlur-side
    ListenAddr      string               // Unix socket path
    AddFriendConfig *config.SignedConfig // bootstrap config the harness signs
    DialingConfig   *config.SignedConfig // similarly
}

// New starts every component in goroutines on local sockets, returns a
// Harness ready for clients to connect.
func New(tb testing.TB) *Harness

// Close tears down every component cleanly; safe to defer.
func (h *Harness) Close()

// ClientFor returns a Neverlur client wired against this harness with
// the given username. The client's hybrid identity is freshly generated
// each call.
func (h *Harness) ClientFor(tb testing.TB, username string) *neverlur.Client

// AdvanceRound moves all of Coordinator + Mixers forward one dialing
// round (driven manually for deterministic tests instead of real clock).
func (h *Harness) AdvanceRound()
```

## Why this lives in Gjallarhorn (not Neverlur)

- The harness includes a Gjallarhorn `coordinator.Server`, `mixnet.MixServer`, `cdn.Server`. Those are Gjallarhorn-internal types; putting the harness in Neverlur would force Neverlur to expose Gjallarhorn's internal interfaces.
- Putting the harness in Gjallarhorn lets Gjallarhorn's CI run the integration test on every Gjallarhorn PR.
- Neverlur's demo CLI imports the harness via the standard cross-module path (see `docs/local-development.md` for the workspace setup that makes this convenient during local dev).

## Consumer-side usage (Neverlur demo CLI)

```go
import "github.com/oluies/gjallarhorn/internal/testharness"

func main() {
    if *role == "alice" {
        h := testharness.New(noopTB{})
        defer h.Close()
        // Listen on Unix socket; bob connects via TCP/Unix.
    } else {
        // Connect to the existing harness over Unix socket.
    }
}
```

The `noopTB` type is a `testing.TB` implementation that no-ops Logf and Fatal-style methods (the harness uses TB for failure reporting; the demo CLI just panics on harness failure).

## Test that ships with the harness

`gjallarhorn/e2e/first_message_test.go::TestE2EFirstMessage`:

1. Stand up a `testharness.Harness` (with 3 mixers + 1 CDN + 1 PKG).
2. Create Alice and Bob clients via `h.ClientFor`.
3. Both register with the PKG.
4. Alice calls `SendFriendRequest("bob@demo.local", nil)`; advance one add-friend round; Bob's mailbox produces an `IncomingFriendRequest`; Bob calls `Approve()`; advance one more round; both clients now have a wheel entry for the other.
5. Alice calls `SendCall(bob, intent)`; advance one dialing round; both clients now have an active `Conversation` with matching `sessionKey`.
6. Alice calls `Conversation.Seal("hello", round, key)`; the packet enters one Gjallarhorn dialing round; Bob's `Conversation.Open` returns "hello".
7. Assert: `Bob.received == []byte("hello")`.
8. Subtests:
   - `TestE2EFirstMessage_HybridConfidentiality_ClassicalCompromise`: handing the verifier only the X25519 half (extracted from the call's `keywheelStart`) fails to derive Bob's `sessionKey`.
   - `TestE2EFirstMessage_HybridConfidentiality_PQCompromise`: symmetric.

## Skip condition

The test skips on `runtime.GOARCH == "arm64"` with the message `"skipped on arm64: vuvuzela.io/crypto/bn256 ships x86_64-only assembly"`. CI on linux/amd64 always runs it.

## Failure modes the harness MUST report distinguishably

- "harness setup failed: <component>: <error>" — the in-process stand-up itself broke (rare; signals a regression in mixnet/coordinator boot)
- "Alice session key != Bob session key" — the keywheel-seed contract was violated by one of the repos
- "conversation packet not delivered after N rounds" — the mixnet routing failed (probably a regression in mixnet code)
- "hybrid carry-through failed" — the X25519-half or PQ-half compromise simulation incorrectly succeeded in deriving the session key

Each is a distinct test diagnostic so a reviewer at PR time can immediately tell which layer regressed.
