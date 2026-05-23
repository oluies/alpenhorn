// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// pqsigDeriveSeedOnly mirrors pqsig.DeriveFromEd25519Seed but returns
// only the 32-byte ML-DSA-65 seed (not the keypair). Used by
// identity_file.go to write the seed into IdentityFile.MLDSA65Seed.
//
// IMPORTANT: the HKDF parameters here MUST match pqsig.DeriveFromEd25519Seed
// byte-for-byte. The pqsig.TestDeriveBindingStable KAT catches any drift
// between the two paths.
func pqsigDeriveSeedOnly(edSeed []byte) (publicSeedUnused, mldsaSeed []byte, err error) {
	if len(edSeed) != 32 {
		return nil, nil, fmt.Errorf("hybrid: ed25519 seed length %d, want 32", len(edSeed))
	}
	const info = "neverlur/v1 pq-id-binding" // must match pqsig.bindingInfo
	const seedSize = 32                      // must match pqsig.SeedSize
	r := hkdf.New(sha512.New, edSeed, nil, []byte(info))
	out := make([]byte, seedSize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}
