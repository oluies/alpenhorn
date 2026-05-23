// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"crypto/rand"
	"sync"
	"testing"
)

// TestConcurrentSignVerify runs Sign and Verify against the same keypair
// from many goroutines. Run with `go test -race ./pqsig` to assert
// thread-safety of the wrappers and CIRCL primitives.
func TestConcurrentSignVerify(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const goroutines = 16
	const iterations = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed byte) {
			defer wg.Done()
			msg := make([]byte, 64)
			if _, err := rand.Read(msg); err != nil {
				t.Errorf("rand.Read: %v", err)
				return
			}
			for i := 0; i < iterations; i++ {
				msg[0] = seed
				msg[1] = byte(i)
				sig, err := Sign(sk, msg)
				if err != nil {
					t.Errorf("Sign: %v", err)
					return
				}
				if !Verify(pk, msg, sig) {
					t.Error("Verify rejected fresh signature under concurrency")
					return
				}
			}
		}(byte(g))
	}
	wg.Wait()
}

// TestConcurrentDerive runs DeriveFromEd25519Seed in parallel with
// distinct seeds. The deterministic derivation MUST be free of shared
// mutable state.
func TestConcurrentDerive(t *testing.T) {
	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seedByte byte) {
			defer wg.Done()
			seed := make([]byte, 32)
			for i := range seed {
				seed[i] = seedByte ^ byte(i)
			}
			if _, _, err := DeriveFromEd25519Seed(seed); err != nil {
				t.Errorf("DeriveFromEd25519Seed: %v", err)
				return
			}
		}(byte(g + 1))
	}
	wg.Wait()
}
