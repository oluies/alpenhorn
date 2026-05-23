# Contract: Conversation Session Key (Neverlur ↔ Gjallarhorn)

**Owner**: Neverlur (producer); Gjallarhorn (consumer)
**Stability**: stable from this commit; changes require a paired-PR design note.

## Producer side (Neverlur)

The conversation session key Gjallarhorn uses for a given `(peer, round)` pair is produced by:

```go
package keywheel // github.com/oluies/neverlur/keywheel

// SessionKey returns the per-round session key for the given peer, or nil
// if no friendship with this peer is yet established or if the wheel has
// already advanced past the requested round.
//
// The returned 32 bytes are the input to nacl/secretbox (or equivalent
// AEAD) on the Gjallarhorn side. Forward secrecy across rounds is
// provided by the wheel's HMAC-SHA256 ratchet.
//
// Post-PQ-cutover, the secret that originally seeded this wheel entry
// (via Wheel.Put during newFriend) was derived via
// hybrid.CombineKEM(hybrid.ContextKeywheelSeed, ...) -- so the session
// key inherits the hybrid combiner's confidentiality property: an
// adversary who later breaks either X25519 or ML-KEM-768 alone cannot
// recover this key.
func (w *Wheel) SessionKey(username string, round uint32) *[32]byte
```

## Consumer side (Gjallarhorn)

Gjallarhorn's `Conversation` state machine receives a session key + round at the moment a call is initiated (via `SendingCall(*neverlur.OutgoingCall)` or `ReceivedCall(*neverlur.IncomingCall)`), then internally rolls it forward via `rollKey` to derive per-round keys for sealing/opening conversation packets.

The consumer contract is:

1. **Treat the returned 32 bytes as opaque.** Do not attempt to decompose them into classical / PQ halves; the wheel exposes only the combined output.
2. **Do not introduce a parallel session-key source.** If Gjallarhorn's `Conversation` ever needs a session key for a friend, it MUST come from `neverlur.Client.GetFriend(peer).SessionKey()` or the equivalent call-based bootstrap. A direct call to `crypto/nacl/box` or `curve25519.X25519` to derive a per-conversation key is a constitutional violation (Principle III: Hybrid, Never Pure).
3. **Forward-secrecy ratcheting is the consumer's job.** Gjallarhorn's `rollKey` ratchets via SHA-512_256 chaining; this is unchanged in Phase A.

## Cross-repo type identity

Both repos refer to the same wheel type via a single import:

```go
import "github.com/oluies/neverlur/keywheel"
```

Two parallel wheels (one per repo) are explicitly forbidden by spec FR-002.

## Versioning

This contract is at version 1, defined by Phase A. Future versions:

- If the wheel's session-key derivation changes (e.g. to include the dialing round number into the HMAC input differently), bump the wheel's internal version byte and document the migration here.
- If the wheel exposes a new method (e.g. `SessionKeyWithIntent(peer, round, intent)`), Phase A's consumers continue to use `SessionKey(peer, round)`; new consumers can opt in.

## Tests

Producer-side tests live in `neverlur/keywheel/keywheel_test.go` and `neverlur/keywheel/keywheel_hybrid_test.go` (already merged). They cover:
- The wheel ratchet produces byte-stable session keys for a fixed seed and round (`TestKeywheelHybridSeed`).
- Two wheels seeded from the same combiner output produce identical session keys (`TestKeywheelHybridSeedAgreement`).

Consumer-side tests are owned by Gjallarhorn (`gjallarhorn/e2e/first_message_test.go`). See `contracts/e2e-test-harness.md`.
