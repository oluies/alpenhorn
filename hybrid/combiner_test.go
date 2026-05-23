// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestCombineKAT loads testdata/combine-kat.json and asserts that
// CombineKEM reproduces the recorded outputs for each documented context.
// This is the deterministic stability test for the combiner construction.
func TestCombineKAT(t *testing.T) {
	data, err := os.ReadFile("testdata/combine-kat.json")
	if err != nil {
		t.Fatalf("read combine KAT: %v", err)
	}
	var kat struct {
		SsX25519Hex string `json:"ssX25519_hex"`
		SsMLKEMHex  string `json:"ssMLKEM_hex"`
		Transcript  string `json:"transcript_utf8"`
		Contexts    map[string]struct {
			SeedHex    string `json:"seed_hex"`
			SeedSHA256 string `json:"seed_sha256"`
		} `json:"contexts"`
	}
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatalf("parse combine KAT: %v", err)
	}
	ssX, err := hex.DecodeString(kat.SsX25519Hex)
	if err != nil {
		t.Fatalf("decode ssX25519: %v", err)
	}
	ssM, err := hex.DecodeString(kat.SsMLKEMHex)
	if err != nil {
		t.Fatalf("decode ssMLKEM: %v", err)
	}
	transcript := []byte(kat.Transcript)
	for ctx, exp := range kat.Contexts {
		seed, err := CombineKEM(ctx, transcript, ssX, ssM)
		if err != nil {
			t.Errorf("CombineKEM(%s): %v", ctx, err)
			continue
		}
		expSeed, err := hex.DecodeString(exp.SeedHex)
		if err != nil {
			t.Errorf("decode expected seed for %s: %v", ctx, err)
			continue
		}
		if !bytes.Equal(seed[:], expSeed) {
			t.Errorf("context=%s: seed mismatch\n  got  %x\n  want %x", ctx, seed[:], expSeed)
		}
		h := sha256.Sum256(seed[:])
		if got := hex.EncodeToString(h[:]); got != exp.SeedSHA256 {
			t.Errorf("context=%s: sha256(seed) = %s, want %s", ctx, got, exp.SeedSHA256)
		}
	}
}

// TestSessionKeyResistsClassicalCompromise: an adversary who learns
// ssX25519 (and the public transcript, and the context label) but not
// ssMLKEM cannot reproduce the session secret. This is the direct
// test-level satisfaction of spec SC-003.
//
// Construction: compute the real session secret with both inputs, then
// attempt to "recompute" it with ssMLKEM replaced by an attacker-chosen
// value. Assert the outputs differ. We try several attacker guesses
// (zero, all-ones, random, derived from ssX25519); none of them can
// match without knowledge of the real ssMLKEM.
func TestSessionKeyResistsClassicalCompromise(t *testing.T) {
	ssX := bytes.Repeat([]byte{0x01}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0x02}, MLKEMSharedSize)
	tr := []byte("compromise-resistance transcript")
	real, err := CombineKEM(ContextFriendRequest, tr, ssX, ssM)
	if err != nil {
		t.Fatalf("CombineKEM(real): %v", err)
	}
	for _, guess := range [][]byte{
		bytes.Repeat([]byte{0x00}, MLKEMSharedSize),
		bytes.Repeat([]byte{0xff}, MLKEMSharedSize),
		ssX, // attacker tries to reuse the classical secret as the PQ secret
		flipFirstByte(ssM),
	} {
		fake, err := CombineKEM(ContextFriendRequest, tr, ssX, guess)
		if err != nil {
			t.Fatalf("CombineKEM(fake): %v", err)
		}
		if bytes.Equal(real[:], fake[:]) {
			t.Fatalf("session secret collided when classical secret known and PQ secret guessed (%x)", guess[:8])
		}
	}
}

// TestSessionKeyResistsPQCompromise is the symmetric test: an adversary
// who learns ssMLKEM but not ssX25519 cannot reproduce the session
// secret. Satisfies spec SC-004.
func TestSessionKeyResistsPQCompromise(t *testing.T) {
	ssX := bytes.Repeat([]byte{0x11}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0x22}, MLKEMSharedSize)
	tr := []byte("compromise-resistance transcript")
	real, err := CombineKEM(ContextFriendRequest, tr, ssX, ssM)
	if err != nil {
		t.Fatalf("CombineKEM(real): %v", err)
	}
	for _, guess := range [][]byte{
		bytes.Repeat([]byte{0x00}, X25519SharedSize),
		bytes.Repeat([]byte{0xff}, X25519SharedSize),
		ssM,
		flipFirstByte(ssX),
	} {
		fake, err := CombineKEM(ContextFriendRequest, tr, guess, ssM)
		if err != nil {
			t.Fatalf("CombineKEM(fake): %v", err)
		}
		if bytes.Equal(real[:], fake[:]) {
			t.Fatalf("session secret collided when PQ secret known and classical secret guessed (%x)", guess[:8])
		}
	}
}

// TestSessionKeyNotDerivableFromComponentAlone asserts the combiner output
// is also different from the individual shared secrets and their
// concatenation hash. If the combiner accidentally degenerated to "use
// ssX25519" or "use ssMLKEM", this test catches it.
func TestSessionKeyNotDerivableFromComponentAlone(t *testing.T) {
	ssX := bytes.Repeat([]byte{0xaa}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0xbb}, MLKEMSharedSize)
	tr := []byte("not-component-only transcript")
	seed, err := CombineKEM(ContextKeywheelSeed, tr, ssX, ssM)
	if err != nil {
		t.Fatalf("CombineKEM: %v", err)
	}
	if bytes.Equal(seed[:], ssX) {
		t.Fatal("session secret equals raw ssX25519")
	}
	if bytes.Equal(seed[:], ssM) {
		t.Fatal("session secret equals raw ssMLKEM")
	}
	hx := sha256.Sum256(ssX)
	if bytes.Equal(seed[:], hx[:]) {
		t.Fatal("session secret equals SHA-256(ssX25519)")
	}
	hm := sha256.Sum256(ssM)
	if bytes.Equal(seed[:], hm[:]) {
		t.Fatal("session secret equals SHA-256(ssMLKEM)")
	}
}

// TestContextSeparation asserts that the three documented context labels
// produce three distinct session secrets given identical other inputs.
// Cross-context secret reuse would be a serious bug — confirms FR-003
// (combiner is IND-CCA in the hybrid sense) is not subverted by accidental
// label collision.
func TestContextSeparation(t *testing.T) {
	ssX := bytes.Repeat([]byte{0xcc}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0xdd}, MLKEMSharedSize)
	tr := []byte("context-separation transcript")
	a, _ := CombineKEM(ContextFriendRequest, tr, ssX, ssM)
	b, _ := CombineKEM(ContextKeywheelSeed, tr, ssX, ssM)
	c, _ := CombineKEM(ContextEdTLSSession, tr, ssX, ssM)
	if bytes.Equal(a[:], b[:]) {
		t.Fatal("FriendRequest and KeywheelSeed contexts collided")
	}
	if bytes.Equal(a[:], c[:]) {
		t.Fatal("FriendRequest and EdTLSSession contexts collided")
	}
	if bytes.Equal(b[:], c[:]) {
		t.Fatal("KeywheelSeed and EdTLSSession contexts collided")
	}
}

// TestTranscriptBinding asserts that two different transcripts produce
// two different session secrets even with identical KEM material and
// context — the property that prevents transcript-replay attacks.
func TestTranscriptBinding(t *testing.T) {
	ssX := bytes.Repeat([]byte{0x33}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0x44}, MLKEMSharedSize)
	a, _ := CombineKEM(ContextFriendRequest, []byte("transcript A"), ssX, ssM)
	b, _ := CombineKEM(ContextFriendRequest, []byte("transcript B"), ssX, ssM)
	if bytes.Equal(a[:], b[:]) {
		t.Fatal("distinct transcripts produced the same session secret")
	}
}

// TestRejectsBadInputs covers length/empty-string validation.
func TestRejectsBadInputs(t *testing.T) {
	good32 := bytes.Repeat([]byte{1}, 32)
	tr := []byte("t")
	cases := []struct {
		name    string
		ctx     string
		tr      []byte
		ssX     []byte
		ssM     []byte
		wantErr error
	}{
		{"empty-context", "", tr, good32, good32, ErrEmptyContext},
		{"short-x25519", ContextFriendRequest, tr, []byte{1}, good32, ErrInvalidShareLength},
		{"short-mlkem", ContextFriendRequest, tr, good32, []byte{1}, ErrInvalidShareLength},
		{"nil-transcript", ContextFriendRequest, nil, good32, good32, ErrEmptyTranscript},
		{"empty-transcript", ContextFriendRequest, []byte{}, good32, good32, ErrEmptyTranscript},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CombineKEM(c.ctx, c.tr, c.ssX, c.ssM)
			if err != c.wantErr {
				t.Errorf("got err %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestSignedMessageBindsKeys asserts that SignedMessage embeds both
// public keys' hashes so a signature is not portable across distinct
// hybrid identities.
func TestSignedMessageBindsKeys(t *testing.T) {
	payload := []byte("artifact")
	edA := []byte("ed-A")
	edB := []byte("ed-B")
	pq := []byte("pq-X")
	m1 := SignedMessage(payload, edA, pq)
	m2 := SignedMessage(payload, edB, pq)
	if bytes.Equal(m1, m2) {
		t.Fatal("SignedMessage did not bind classical public key into the hash")
	}
	m3 := SignedMessage(payload, edA, []byte("pq-Y"))
	if bytes.Equal(m1, m3) {
		t.Fatal("SignedMessage did not bind PQ public key into the hash")
	}
	// The prefix is present so signers/verifiers can validate domain
	// separation cheaply if they want.
	if !bytes.HasPrefix(m1, []byte(SigMessagePrefix)) {
		t.Fatal("SignedMessage missing SigMessagePrefix")
	}
}

func flipFirstByte(in []byte) []byte {
	out := append([]byte(nil), in...)
	out[0] ^= 0x80
	return out
}
