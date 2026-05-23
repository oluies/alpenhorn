// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"testing"
)

// FuzzCombineKEM asserts that, for any input passing the size and
// non-emptiness checks, CombineKEM returns a 32-byte secret that is NOT
// byte-equal to either of its component shared secrets.
//
// The fuzzer chooses the byte slices freely; we normalize lengths inside
// the fuzz function so the validation gates do not always trip. Run via:
//
//	go test -fuzz=FuzzCombineKEM -fuzztime=30s ./hybrid
//
// CI runs a single seed pass; the explicit go-fuzz invocation is operator-
// triggered when adversarial coverage is wanted.
func FuzzCombineKEM(f *testing.F) {
	// Seed corpus from the recorded KAT plus a few simple inputs.
	f.Add([]byte("transcript-a"), []byte("seed-X"), []byte("seed-M"))
	f.Add([]byte{0x00, 0x01, 0x02}, []byte{0x10}, []byte{0x20})
	f.Add([]byte("the quick brown fox"), []byte{0xff}, []byte{0xee})

	f.Fuzz(func(t *testing.T, transcript, xSeed, mSeed []byte) {
		if len(transcript) == 0 {
			t.Skip()
		}
		// Stretch the fuzz-chosen seeds to the required lengths by tiling.
		// This keeps the surface broad without rejecting most calls.
		ssX := tileBytes(xSeed, X25519SharedSize)
		ssM := tileBytes(mSeed, MLKEMSharedSize)

		for _, ctx := range []string{ContextFriendRequest, ContextKeywheelSeed, ContextEdTLSSession} {
			out, err := CombineKEM(ctx, transcript, ssX, ssM)
			if err != nil {
				// Validation errors are acceptable; nothing else is.
				if err != ErrEmptyTranscript && err != ErrEmptyContext && err != ErrInvalidShareLength {
					t.Fatalf("unexpected error: %v", err)
				}
				continue
			}
			if out == nil {
				t.Fatal("CombineKEM returned nil on accepted input")
			}
			if bytes.Equal(out[:], ssX) {
				t.Fatalf("session secret equals raw ssX25519 (ctx=%q transcript=%x)", ctx, transcript)
			}
			if bytes.Equal(out[:], ssM) {
				t.Fatalf("session secret equals raw ssMLKEM (ctx=%q transcript=%x)", ctx, transcript)
			}
		}
	})
}

// tileBytes returns a byte slice of length n by repeating in. If in is
// empty it returns a slice of zero bytes.
func tileBytes(in []byte, n int) []byte {
	out := make([]byte, n)
	if len(in) == 0 {
		return out
	}
	for i := range out {
		out[i] = in[i%len(in)]
	}
	return out
}
