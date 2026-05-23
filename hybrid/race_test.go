// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"sync"
	"testing"
)

// TestConcurrentCombineKEM exercises CombineKEM from many goroutines with
// distinct inputs. Run with `go test -race ./hybrid`.
func TestConcurrentCombineKEM(t *testing.T) {
	const goroutines = 16
	const iterations = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(label byte) {
			defer wg.Done()
			ssX := bytes.Repeat([]byte{label}, X25519SharedSize)
			ssM := bytes.Repeat([]byte{^label}, MLKEMSharedSize)
			tr := []byte{label}
			for i := 0; i < iterations; i++ {
				tr = append(tr, byte(i))
				if _, err := CombineKEM(ContextFriendRequest, tr, ssX, ssM); err != nil {
					t.Errorf("CombineKEM: %v", err)
					return
				}
			}
		}(byte(g + 1))
	}
	wg.Wait()
}

// TestConcurrentIdentityGen runs GenerateHybridIdentity in parallel.
// The full pipeline (Ed25519 keygen + HKDF + ML-DSA-65 keygen) must
// remain free of shared mutable state.
func TestConcurrentIdentityGen(t *testing.T) {
	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			id, err := GenerateHybridIdentity()
			if err != nil {
				t.Errorf("GenerateHybridIdentity: %v", err)
				return
			}
			if err := id.VerifyBinding(); err != nil {
				t.Errorf("VerifyBinding: %v", err)
				return
			}
		}()
	}
	wg.Wait()
}
