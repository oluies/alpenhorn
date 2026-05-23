# Contract: Demo CLI (`neverlur-conversation-demo`)

**Owner**: Neverlur
**Binary path**: `cmd/neverlur-conversation-demo/`
**Stability**: not for production; UX may change between releases. The binary file header explicitly states this (spec FR-016).

## Invocation

```sh
# Terminal 1 (Alice, also hosts the in-memory harness):
$ neverlur-conversation-demo -as alice

# Terminal 2 (Bob, connects to Alice's harness):
$ neverlur-conversation-demo -as bob
```

Both invocations block in an interactive REPL until Ctrl-C.

### Flags

- `-as {alice|bob}` (required) — which role this terminal runs.
- `-username STR` (optional) — overrides the default username (default `<role>@demo.local`).
- `-harness PATH` (optional) — overrides the Unix-socket address for the harness (default `$XDG_RUNTIME_DIR/neverlur-demo.sock`; alice creates it, bob connects).
- `-id-path PATH` (optional) — where to persist the ephemeral demo identity seed (default `$XDG_CACHE_HOME/neverlur-demo/<role>.id`).

## REPL behavior

### Startup banner

```
neverlur-conversation-demo — demo build, NOT for production messaging
This binary persists an ephemeral Ed25519 seed in plaintext at <id-path>.
The seed is deleted on clean exit.

[alice] starting in-memory harness at unix:<harness-path>
[alice] registered as alice@demo.local
[alice] waiting for friend request from bob...
```

### Friend-discovery prompts

Alice's terminal, after Bob registers:

```
[alice] type a username to send a friend request, or 'q' to quit:
> bob@demo.local
[alice] friend request sent; waiting for bob to approve...
```

Bob's terminal:

```
[bob] incoming friend request from alice@demo.local; approve? [y/N]
> y
[bob] approved
[alice] friend confirmed
```

### Conversation prompts

After friend confirmation:

```
[alice] you can now message bob@demo.local
[alice] message:
> hello bob
[alice] sent (waiting for next dialing round...)
[bob] alice@demo.local: hello bob
```

### Errors

| Trigger | Message | Behavior |
|---|---|---|
| Empty message typed | `"empty message; type something to send"` | Re-prompt |
| Message > `convo.ConvoMessageSize` bytes | `"message too long: <N> bytes, max <BUDGET>"` | Re-prompt |
| Non-UTF-8 input | `"input is not valid UTF-8"` | Re-prompt |
| Harness disconnect (bob only) | `"harness gone; exiting"` | Exit 1 |
| Friend request to unknown user | `"no such user: <name>"` | Re-prompt |
| Ctrl-C | (no message) | Tear down, delete identity file, exit 0 |

## Validation contract (spec FR-014)

The CLI validates every user-typed message at the input boundary before submitting it to the conversation layer:

1. `len(input) > 0` — empty rejected.
2. `len(input) <= convo.ConvoMessageSize` — oversized rejected with the budget quoted in the error message.
3. `utf8.Valid(input)` — non-UTF-8 rejected.

The conversation layer never sees an invalid message; defense-in-depth on the protocol side is not weakened by this CLI-side check.

## Clean-exit contract (spec FR-015)

On Ctrl-C in either terminal:

1. The CLI's signal handler runs.
2. Active `Conversation` is closed.
3. `neverlur.Client.Close()` is called.
4. (Alice only) The harness is torn down (kills all in-process Goroutines, closes the Unix socket).
5. The ephemeral identity file (E3) is `os.Remove`'d.
6. Exit 0.

Any temp directories the harness created are also cleaned up (the harness's `Close()` handles this on its end).

No orphaned subprocesses (none are spawned — everything is in-process Goroutines that exit on context cancellation).

## Source-code header (spec FR-016)

Every `.go` file in `cmd/neverlur-conversation-demo/` begins with:

```go
// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// neverlur-conversation-demo is a developer tool that demonstrates a
// hybrid-keywheel-seeded conversation packet round-trip between two
// terminals on one laptop. It is NOT production messaging software:
//   - It persists an Ed25519 seed in plaintext.
//   - It runs the coordinator, mixers, CDN, and PKG in-process; in
//     production these are independent services.
//   - It has no UX hardening (no offline queue, no message history,
//     no key rotation flow).
// For real messaging, see the planned mobile app in Phase B.
```

## Out of scope

- No multi-conversation support (one peer per session).
- No message history.
- No offline behavior; both terminals must be running simultaneously for the demo to complete.
- No notifications.
- No theme / coloring beyond what the user's terminal does by default.
