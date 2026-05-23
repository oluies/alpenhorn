# Quickstart: Post-Quantum Hybrid Cryptography

**Feature**: 001-pq-hybrid-crypto
**Audience**: a developer or operator coming to this branch for the first time who needs to validate that the migration works end-to-end on a single machine.

## Prerequisites

- Go 1.25+ (`go version`)
- This branch (`001-pq-hybrid-crypto`) checked out
- No GPU, no special hardware

## 1. Build everything

```bash
go build ./...
go test ./...
```

All KAT tests under `pqsig/`, `pqkem/`, and `hybrid/` MUST pass. If any KAT fails, do not continue — the FIPS 203 / FIPS 204 contract is broken and every downstream test is meaningless.

## 2. Generate a hybrid guardian identity

```bash
go run ./cmd/guardian/neverlur-guardian-keygen \
    -out alice.neverlur-id-v2
```

The tool writes `alice.neverlur-id-v2` (mode 0600) carrying both the Ed25519 seed and the derived ML-DSA-65 seed (R4 binding). To confirm the binding:

```bash
go run ./cmd/neverlur-pq-posture identity -file alice.neverlur-id-v2
```

Expected output: `binding=ok ed25519_pub=<base32> mldsa65_pub=<base32 truncated> created=2026-05-23T…`.

## 3. Sign a config under the hybrid identity

```bash
go run ./cmd/guardian/neverlur-guardian-sign-config \
    -id alice.neverlur-id-v2 \
    -in  testdata/config-template.json \
    -out testdata/config-signed.json
```

The output is a v2 `SignedConfig` carrying a hybrid signature. Inspect:

```bash
jq '.Version, .Signatures' testdata/config-signed.json
# Version: 2
# Signatures: { "<base32>": "<base64 of Ed||PQ, 3373 bytes>" }
```

## 4. Verify the config

```bash
go run ./cmd/neverlur-pq-posture verify-config -file testdata/config-signed.json
```

Expected: `verify=ok hybrid=yes guardians=1`.

## 5. End-to-end friend-request demo

```bash
cd alpenhorn_test  # or wherever the e2e harness lives in this branch
go test -run TestE2EHybridFriendRequest -v
```

This test stands up an in-process coordinator, PKG, mixer, and CDN; runs two clients (Alice and Bob) with freshly-generated hybrid identities; sends a friend request from Alice to Bob; and asserts:
- The introduction on the wire is v2 (first byte 0x02, total bytes 6695).
- Both halves of Bob's hybrid signature on the resulting friendship attestation verify.
- The keywheel seed at Alice and Bob is byte-identical and equals `hybrid.CombineKEM(ContextKeywheelSeed, transcript, ssX25519, ssMLKEM)`.

## 6. Cutover behavior

To exercise the cutover:

```bash
# Pre-cutover: classical-only peer accepted with warning
NEVERLUR_PQ_CUTOVER=2099-01-01T00:00:00Z go test ./config -run TestCutoverAcceptsV1Before -v

# Post-cutover: classical-only peer rejected
NEVERLUR_PQ_CUTOVER=2020-01-01T00:00:00Z go test ./config -run TestCutoverRejectsV1After -v
```

Both tests MUST pass.

## 7. Operator posture report

```bash
go run ./cmd/neverlur-pq-posture report -config testdata/config-signed.json
```

Produces a JSON + tabular report listing every peer/artifact and its posture (`hybrid` / `classical-only` / `unverifiable`). This is the operator surface for FR-013 and SC-005.

## 8. Performance sanity check

```bash
go test -run=^$ -bench=. -benchtime=2s ./addfriend ./dialing ./config ./edtls ./hybrid
```

Compare against the captured baseline (`benchmarks/baseline-pre-pq.txt`, committed at the start of this branch). No benchmark should exceed 1.25× its baseline number; CI enforces this gate (SC-007).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `pqsig kat: vector 3 mismatch` | CIRCL version drift | Verify `go.mod` pins the expected CIRCL version (`go list -m github.com/cloudflare/circl`); re-pin if needed |
| `error: pq identity binding failed` on load | hand-edited identity file, or v1 file regenerated incorrectly | Delete the v2 file; re-run keygen which will re-derive the binding |
| `event=pq.reject artifact=signed-config` in logs after upgrade | a peer is still on the classical-only build past the cutover | Either upgrade that peer or push the cutover instant; do not silently disable the gate |
| benchmark fails 1.25× check on `dialing/mixer` only | likely the ML-KEM-768 ciphertext bandwidth on the round; check the mixer's network budget | Profile the round; consider whether a parameter-set step-down (ML-KEM-512) is justified per SC-007's escape hatch — requires operator sign-off |
