---

description: "Task list for 002-conversation-wiring (Neverlur side)"
---

# Tasks: Conversation Wiring (Neverlur side, Phase A)

**Input**: Design documents in `specs/002-conversation-wiring/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: NOT required for Neverlur side. The Phase A integration test + the static-check test live on the Gjallarhorn side per `research.md` R4 / Gjallarhorn `001-conversation-wiring/contracts/e2e-test-cases.md`. The Neverlur-side demo CLI is exercised by manual smoke test (US4) and indirectly by the Gjallarhorn-side integration test that consumes the same harness.

**Organization**: Tasks are grouped by user story per the spec.md priorities. Phase A's Neverlur side is unusually light: nearly all real implementation work is on the Gjallarhorn side; Neverlur owns only the demo CLI binary plus a dependency wire-up.

## Format: `[ID] [P?] [Story?] Description with file path`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 / US4 — maps to spec.md user stories
- All paths repository-root-relative

## Path Conventions

Single Go module at the repository root. The Phase A Neverlur additions all live under `cmd/neverlur-conversation-demo/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Wire up the cross-repo dependency that the demo CLI needs.

- [ ] T001 Add `require github.com/oluies/gjallarhorn v0.0.0-<commit-sha-of-merged-Gjallarhorn-PR-#4-and-paired-impl>` to `go.mod` and `go mod tidy`. Until Gjallarhorn's Phase A implementation lands, this is a placeholder; the actual commit-sha gets filled in after Gjallarhorn merges its harness package.
- [ ] T002 [P] Update `docs/local-development.md` if any new convention emerges from Phase A (e.g. note that the `~/projects/go.work` setup is now load-bearing for running the demo CLI, not just convenience).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Nothing to do on the Neverlur side. The foundational work for Phase A is hosting the test harness, which lives on Gjallarhorn (per `internal/testharness/` in Gjallarhorn's plan). This phase is empty.

**⚠️ External blocker**: All Phase 3+ tasks below depend on the Gjallarhorn-side Phase A implementation landing first. Specifically:
- Gjallarhorn's `internal/testharness` package must be exported and usable.
- Gjallarhorn's rebrand-finishing fix in `cmd/gjallarhorn-client/alpenhorn.go` must be merged.
- Gjallarhorn's dead `replace vuvuzela.io/alpenhorn` must be removed from `go.mod`.

Once those land on Gjallarhorn master, T001 can pin to the merged commit-sha and the demo CLI work below can proceed.

---

## Phase 3: User Story 1 - Friended pair exchanges a first message (Priority: P1)

**Goal**: Verify that the existing Neverlur friend-discovery → Gjallarhorn conversation handoff still works under the hybrid keywheel, with no new Neverlur code required.

**Independent Test**: The Gjallarhorn-side `TestE2EFirstMessage` (described in Gjallarhorn `001-conversation-wiring/contracts/e2e-test-cases.md`) covers this. From the Neverlur side, the verification is "no regression": running the existing Neverlur unit tests on master + the Phase 1 dependency bump in T001 should leave every existing Neverlur test green.

### Implementation for User Story 1

- [ ] T003 [US1] Verify no Neverlur regression: run `go test ./...` (skipping the bn256-affected paths on arm64; full suite on linux/amd64 CI) and confirm zero failures introduced by the T001 dependency bump.

**Checkpoint**: US1 — no functional Neverlur code change. The property is delivered by the existing keywheel pathway (hybrid post-PR-#4) consumed unchanged on the Gjallarhorn side.

---

## Phase 4: User Story 2 - Conversation confidentiality inherits the PQ hybrid property (Priority: P1)

**Goal**: Ensure no Neverlur change weakens the hybrid combiner output that feeds the keywheel seed.

**Independent Test**: The existing `keywheel/keywheel_hybrid_test.go` + `keywheel_seed_test.go` (already on Neverlur master) cover this property at the seed-derivation level. The Gjallarhorn-side `TestE2EFirstMessage_HybridConfidentiality_*` subtests cover the end-to-end carry-through. No new Neverlur tests are required.

### Implementation for User Story 2

- [ ] T004 [US2] Verify no regression in `keywheel`/`hybrid` packages: `go test -race -count=1 ./keywheel ./hybrid ./pqkem ./pqsig` continues to pass with the same test counts (57 passing tests as of PR #4 merge).

**Checkpoint**: US2 — no functional Neverlur code change. The hybrid combiner output is unchanged; the property is structurally enforced by the existing test suite.

---

## Phase 5: User Story 3 - Developer can prove the round-trip works in CI (Priority: P2)

**Goal**: From Neverlur's side, ensure the existing CI doesn't regress and the cross-repo signal flow is documented.

**Independent Test**: A Neverlur PR that intentionally regresses the `Wheel.SessionKey` output triggers a CI failure on the next Gjallarhorn PR that pulls the new Neverlur commit. This is verified by manually setting up the chain once after Gjallarhorn's Phase A CI lands.

### Implementation for User Story 3

- [ ] T005 [US3] Add a paragraph to `docs/local-development.md` documenting the cross-repo CI signal flow (Neverlur PR → Gjallarhorn pulls merged commit-sha → Gjallarhorn CI catches regression). Already partially covered; this task confirms it's accurate after Phase A lands.

**Checkpoint**: US3 — documentation-only Neverlur task. The actual integration test lives on Gjallarhorn.

---

## Phase 6: User Story 4 - Demonstrator can run two terminals and watch a real message flow (Priority: P3)

**Goal**: Land the `neverlur-conversation-demo` binary so a person can drive the full friend-discovery + first-conversation-message journey from two terminals on one laptop.

**Independent Test**: Manual smoke test per `quickstart.md` step 4. Launch terminal A with `-as alice`, terminal B with `-as bob`; complete the demo journey; observe Bob's terminal print Alice's message.

### Implementation for User Story 4

- [ ] T006 [P] [US4] Create the binary entry point at `cmd/neverlur-conversation-demo/main.go` with flag parsing per `contracts/demo-cli.md` (`-as`, `-username`, `-harness`, `-id-path`), Ctrl-C signal handling, and dispatch to either `runAlice()` or `runBob()`.
- [ ] T007 [P] [US4] Create the in-memory harness wrapper at `cmd/neverlur-conversation-demo/inmemory.go` that calls `testharness.New(noopTB{}, testharness.OptionListenAddr(*harnessFlag))` from Gjallarhorn (Alice's process hosts; Bob's process connects). Define the local `noopTB` type that no-ops `Logf` / `Fatal` for the harness's `testing.TB` parameter.
- [ ] T008 [US4] Create the Alice flow at `cmd/neverlur-conversation-demo/alice.go`: register with PKG, wait for friend request from Bob, approve, accept incoming call from Bob, prompt for message, type message, await delivery confirmation. Validate user input per `contracts/demo-cli.md` FR-014 (non-empty, UTF-8, length ≤ `convo.ConvoMessageSize`).
- [ ] T009 [US4] Create the Bob flow at `cmd/neverlur-conversation-demo/bob.go`: register with PKG, send friend request to alice, wait for approval, initiate call, send first message after confirmation, await receive of Alice's response. Same input validation.
- [ ] T010 [P] [US4] Add the source-code header to each new file per `contracts/demo-cli.md` "Source-code header" section — the explicit "NOT production messaging software" notice with the four-bullet caveat list.
- [ ] T011 [US4] Add ephemeral identity persistence at `cmd/neverlur-conversation-demo/identity.go` (or fold into `main.go`): read or generate the Ed25519 seed at `$XDG_CACHE_HOME/neverlur-demo/<role>.id` with mode 0600; delete on clean exit per FR-015.
- [ ] T012 [US4] Manual smoke test: follow `quickstart.md` step 4 on one laptop. Confirm the full journey completes within 5 minutes wall-clock per SC-004. Confirm Ctrl-C in either terminal exits cleanly with no orphaned subprocesses or temp files (run `ls ~/.cache/neverlur-demo/` after exit; expect empty).

**Checkpoint**: US4 — the demo CLI is functional and the manual smoke test passes.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T013 [P] Update `README.md` to mention the new `cmd/neverlur-conversation-demo/` binary in the binaries list, with a one-line description and a link to `quickstart.md`.
- [ ] T014 [P] Add an entry to `docs/local-development.md` for the demo CLI — how to run it, what the harness socket convention is, and the explicit "demo-only" warning.
- [ ] T015 [P] Verify `gofmt -l .` is silent and `go vet ./...` is green on the merged branch before opening the PR. (CI gates this too; this is a pre-PR self-check.)
- [ ] T016 [P] Commit message audit: every commit on this branch touching `cmd/neverlur-conversation-demo/` must include the constitution-mandated "Threat-model impact" paragraph (Principle II). For these commits the paragraph is short — the demo doesn't change protocol behavior, but the demo's UX surface (handling untrusted user input from stdin) is worth noting once.

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup)**: depends on Gjallarhorn's Phase A implementation landing (specifically the `internal/testharness` package being exported). T001 pins to a specific Gjallarhorn commit-sha.
- **Phase 2 (Foundational)**: empty. No Neverlur foundational work.
- **Phase 3 (US1) and Phase 4 (US2)**: both depend on Phase 1. They are verification-only tasks (no functional Neverlur change); can run after T001 lands.
- **Phase 5 (US3)**: depends on Phases 3 + 4 (documentation finalized after the property is verified).
- **Phase 6 (US4)**: depends on Phase 1 (the demo CLI imports the Gjallarhorn harness via T001's pinned version). T006–T012 are the demo CLI implementation.
- **Phase 7 (Polish)**: depends on Phase 6 (the README and docs entries reference the demo binary).

### User-story dependencies summary

- US1 (P1): Phase A is mostly delivered by existing code; Neverlur verifies no regression (T003).
- US2 (P1): Same — verify no regression (T004).
- US3 (P2): Documentation only (T005).
- US4 (P3): Demo CLI implementation (T006–T012); 5–7 new files in one directory.

### Within Phase 6 (US4)

- T006, T007, T010 in parallel — different files, no inter-task dependencies.
- T008 and T009 depend on T006 (they wire into the `main.go` dispatch) and on T007 (they need the harness wrapper).
- T011 can land in parallel with T008/T009 if it's a separate file.
- T012 is the final integration smoke test; runs last.

### Parallel opportunities

- T002 in Phase 1.
- T013 / T014 / T015 / T016 in Phase 7.
- T006 / T007 / T010 within Phase 6.

---

## Parallel Example: Phase 6 implementation

```bash
# After T001 lands the Gjallarhorn dependency pin, three parallel
# starts on Phase 6:
Task: "Create cmd/neverlur-conversation-demo/main.go per T006"
Task: "Create cmd/neverlur-conversation-demo/inmemory.go per T007"
Task: "Add source-code headers per T010"
# T008 + T009 then depend on T006/T007:
Task: "Create cmd/neverlur-conversation-demo/alice.go per T008"
Task: "Create cmd/neverlur-conversation-demo/bob.go per T009"
# T011 in parallel:
Task: "Add identity persistence per T011"
# T012 final:
Task: "Manual smoke test per T012"
```

---

## Implementation Strategy

### MVP First (US4 only)

Neverlur's MVP for Phase A is the demo CLI (US4). US1, US2, US3 are verification-only tasks that confirm no Neverlur regression; they ride on the Gjallarhorn-side delivery.

1. Phase 1 Setup (T001 + T002) — gets the Gjallarhorn dependency in place.
2. Phase 6 US4 (T006–T012) — the demo CLI binary.
3. Phase 7 polish (T013–T016) — README + docs + lint.

The verification tasks (T003, T004, T005) ride alongside as quick checkpoints; they don't block anything.

### Sequencing across repos

- **Step 1** (Gjallarhorn): land Gjallarhorn's Phase A implementation per `gjallarhorn/specs/001-conversation-wiring/tasks.md`. Most of Phase A's actual code lives here.
- **Step 2** (Neverlur): pin to the merged Gjallarhorn commit-sha (T001), implement the demo CLI (Phase 6), polish (Phase 7).
- **Step 3** (both repos): manual smoke test of the demo CLI end-to-end (T012), confirm the Gjallarhorn-side `TestE2EFirstMessage` still passes on the linked commit-sha.

### Parallel team strategy

One developer:
1. Wait for Gjallarhorn Phase A to merge.
2. Run T001 → T006/T007/T010 in parallel → T008/T009/T011 → T012.

Two developers:
1. Same; the demo CLI work splits naturally across two people (one does alice.go + bob.go + identity, the other does main.go + inmemory.go + harness integration).

---

## Notes

- Phase A's Neverlur side is short because the discovery in `research.md` R1 found that the conversation-layer wiring already exists on the Gjallarhorn side. The hybrid keywheel seed flows through unchanged.
- Every commit in this branch (touching `cmd/neverlur-conversation-demo/` or `docs/local-development.md`) MUST include a "Threat-model impact" paragraph per Constitution Principle II. For demo-CLI commits the paragraph is brief (no protocol change; input validation is the main surface).
- The demo CLI is explicitly NOT production-quality. The source headers, the README entry, and the docs entry all repeat this warning.
- Cross-repo coordination per the Compatibility section: this Neverlur work depends on Gjallarhorn's Phase A landing first. The two repos do NOT need to ship paired PRs here — the implementation is sequential, with Neverlur consuming a pinned Gjallarhorn version after Gjallarhorn merges.
