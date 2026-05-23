// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import (
	"bytes"
	"sync"
	"testing"
)

// TestConcurrentOperations runs Generate, Encap, Decap, and Pack/Unpack
// from many goroutines simultaneously. Run with `go test -race ./pqkem`
// to assert the wrappers (and the underlying CIRCL primitives) carry no
// hidden shared state.
//
// CIRCL claims thread-safety for the public mlkem768 API; this test
// verifies that our re-export and our additional code paths do not
// introduce any.
func TestConcurrentOperations(t *testing.T) {
	const goroutines = 16
	const iterations = 8

	// Each goroutine runs an independent keypair through Encap/Decap.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pk, sk, err := GenerateKey()
				if err != nil {
					t.Errorf("GenerateKey: %v", err)
					return
				}
				ct, ssA, err := Encapsulate(pk)
				if err != nil {
					t.Errorf("Encapsulate: %v", err)
					return
				}
				ssB, err := Decapsulate(sk, ct)
				if err != nil {
					t.Errorf("Decapsulate: %v", err)
					return
				}
				if !bytes.Equal(ssA, ssB) {
					t.Error("decap mismatch under concurrency")
					return
				}
				if _, err := UnpackPublicKey(PackPublicKey(pk)); err != nil {
					t.Errorf("UnpackPublicKey: %v", err)
					return
				}
				if _, err := UnpackPrivateKey(PackPrivateKey(sk)); err != nil {
					t.Errorf("UnpackPrivateKey: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentSharedPublicKey: many goroutines encapsulate to the
// SAME public key in parallel. CIRCL's PublicKey is supposed to be safe
// for concurrent encapsulation; this test catches any regression.
func TestConcurrentSharedPublicKey(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const goroutines = 16
	const iterations = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ct, ssA, err := Encapsulate(pk)
				if err != nil {
					t.Errorf("Encapsulate: %v", err)
					return
				}
				ssB, err := Decapsulate(sk, ct)
				if err != nil {
					t.Errorf("Decapsulate: %v", err)
					return
				}
				if !bytes.Equal(ssA, ssB) {
					t.Error("decap mismatch under shared-pk concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}
