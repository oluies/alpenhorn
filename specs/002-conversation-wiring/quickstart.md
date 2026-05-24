# Quickstart: Conversation Wiring (Phase A)

**Feature**: 002-conversation-wiring
**Audience**: a developer or demonstrator coming to this branch (and Gjallarhorn's companion branch) for the first time who wants to see one message round-trip between two friended users.

## Prerequisites

- Go 1.25+
- Linux/amd64 OR macOS/arm64 with the understanding that the integration test cannot run on arm64 (pre-existing `vuvuzela.io/crypto/bn256` assembly limitation).
- Both repos cloned as siblings:
  ```
  ~/projects/
  ├── neverlur/      (this repo)
  └── gjallarhorn/
  ```
- Local `~/projects/go.work` per `docs/local-development.md`.

## 1. Confirm the workspace is active

```sh
$ cd ~/projects/neverlur
$ go env GOWORK
/Users/<you>/projects/go.work
```

Empty output means the workspace is missing; see `docs/local-development.md`.

## 2. Verify both repos build

```sh
# On linux/amd64 (CI surface):
$ cd ~/projects/neverlur && go build ./...
$ cd ~/projects/gjallarhorn && go build ./...
# On macOS/arm64 (limited): only the bn256-free packages build:
$ cd ~/projects/neverlur && go build ./pqkem ./pqsig ./hybrid ./keywheel
```

## 3. Run the Phase A integration test (linux/amd64 only)

```sh
$ cd ~/projects/gjallarhorn
$ go test -run TestE2EFirstMessage -timeout 5m ./e2e/...
ok  	github.com/oluies/gjallarhorn/e2e	28.4s
```

Expected:
- Test completes within 5 minutes wall-clock (per SC-001).
- One round-trip message ("hello") exchanges between in-process Alice and Bob.
- Subtest `TestE2EFirstMessage_HybridConfidentiality_ClassicalCompromise` confirms classical-half compromise cannot derive the session key (SC-002).
- Subtest `TestE2EFirstMessage_HybridConfidentiality_PQCompromise` confirms the same for the PQ half (SC-003).

On arm64:
```sh
$ go test -run TestE2EFirstMessage -timeout 5m ./e2e/...
--- SKIP: TestE2EFirstMessage (0.00s)
    skipped on arm64: vuvuzela.io/crypto/bn256 ships x86_64-only assembly
ok  	github.com/oluies/gjallarhorn/e2e	0.40s
```

## 4. Run the demo CLI (any platform)

Terminal 1 (Alice — also starts the in-memory harness):

```sh
$ cd ~/projects/neverlur
$ go run ./cmd/neverlur-conversation-demo -as alice
neverlur-conversation-demo — demo build, NOT for production messaging
This binary persists an ephemeral Ed25519 seed in plaintext at /Users/<you>/.cache/neverlur-demo/alice.id.
The seed is deleted on clean exit.

[alice] starting in-memory harness at unix:/tmp/neverlur-demo.sock
[alice] registered as alice@demo.local
[alice] waiting for friend request from bob...
```

Terminal 2 (Bob — connects to Alice's harness):

```sh
$ cd ~/projects/neverlur
$ go run ./cmd/neverlur-conversation-demo -as bob
neverlur-conversation-demo — demo build, NOT for production messaging
[...]
[bob] registered as bob@demo.local
[bob] type 'fr alice@demo.local' to send a friend request, or 'q' to quit:
> fr alice@demo.local
[bob] friend request sent; waiting for alice to approve...
```

Back in Alice's terminal:

```
[alice] incoming friend request from bob@demo.local; approve? [y/N]
> y
[alice] approved
[bob] friend confirmed
[alice] you can now message bob@demo.local
[alice] message:
> hello bob
[alice] sent (waiting for next dialing round...)
```

In Bob's terminal:

```
[bob] alice@demo.local: hello bob
```

Ctrl-C in either terminal exits both cleanly. The ephemeral identity files (`~/.cache/neverlur-demo/{alice,bob}.id`) are deleted.

## 5. Validate the no-classical-fallback property

The test in step 3 covers it programmatically. To eyeball it manually:

```sh
$ cd ~/projects/gjallarhorn
$ grep -rn 'box.Precompute\|curve25519.X25519' convo/ cmd/gjallarhorn-client/ 2>/dev/null
# Expected: no output (zero matches) — every classical-only call site has
# been removed from the conversation path. Any match here is a Phase A
# regression and must be fixed before merge.
```

The same grep is implemented as a Go test in `gjallarhorn/e2e/no_classical_session_key_test.go`; CI runs it on every Gjallarhorn PR.

## 6. End-of-session cleanup

The demo CLI cleans up automatically on Ctrl-C. To confirm:

```sh
$ ls ~/.cache/neverlur-demo/ 2>/dev/null
# Expected: directory empty or "No such file or directory".

$ lsof /tmp/neverlur-demo.sock 2>/dev/null
# Expected: empty (the harness socket is closed).
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `go env GOWORK` returns empty | go.work missing or wrong dir | Create `~/projects/go.work` per `docs/local-development.md` |
| `conflicting replacements for vuvuzela.io/alpenhorn` | Gjallarhorn's dead `replace` not yet removed | Apply the Gjallarhorn-side companion plan; this is one of its deliverables |
| `cmd/gjallarhorn-client/alpenhorn.go:36:53: undefined: alpenhorn` | Gjallarhorn rebrand incompleteness | Apply the Gjallarhorn-side companion plan; this is also one of its deliverables |
| `TestE2EFirstMessage_HybridConfidentiality_ClassicalCompromise` fails | Something on the Neverlur side regressed the hybrid combiner | Re-run `go test ./hybrid` and `./keywheel` on Neverlur; check whether `TestKeywheelHybridSeed` still passes |
| Demo terminals don't see each other | Stale `/tmp/neverlur-demo.sock` from a previous unclean exit | `rm /tmp/neverlur-demo.sock` and re-launch alice |
| Demo CLI prints `harness gone; exiting` on bob's side | Alice's terminal exited (Ctrl-C or panic) | Restart both terminals |
