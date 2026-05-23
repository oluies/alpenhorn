// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import (
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// TestCIRCLConstantsMatchScheme guards against silent constant drift when
// upgrading CIRCL: if a future release changes a size, this test fails
// loudly rather than letting `make([]byte, PublicKeySize)` start producing
// wrong-sized buffers used in wire encoding.
//
// FIPS 203 fixes the ML-KEM-768 sizes, so any drift would be a CIRCL bug,
// but the test is cheap and catches it at upgrade time rather than at
// "why is the friend-request mailbox not parsing".
func TestCIRCLConstantsMatchScheme(t *testing.T) {
	sch := mlkem768.Scheme()
	if got, want := sch.PublicKeySize(), PublicKeySize; got != want {
		t.Errorf("PublicKeySize: pqkem=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.PrivateKeySize(), PrivateKeySize; got != want {
		t.Errorf("PrivateKeySize: pqkem=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.CiphertextSize(), CiphertextSize; got != want {
		t.Errorf("CiphertextSize: pqkem=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.SharedKeySize(), SharedKeySize; got != want {
		t.Errorf("SharedKeySize: pqkem=%d, CIRCL Scheme=%d", want, got)
	}
	// FIPS 203 mandates 1184 / 2400 / 1088 / 32. Hard-code them as the
	// final backstop so a CIRCL constant rename can't silently re-route
	// the test.
	if PublicKeySize != 1184 {
		t.Errorf("FIPS 203: PublicKeySize must be 1184, got %d", PublicKeySize)
	}
	if PrivateKeySize != 2400 {
		t.Errorf("FIPS 203: PrivateKeySize must be 2400, got %d", PrivateKeySize)
	}
	if CiphertextSize != 1088 {
		t.Errorf("FIPS 203: CiphertextSize must be 1088, got %d", CiphertextSize)
	}
	if SharedKeySize != 32 {
		t.Errorf("FIPS 203: SharedKeySize must be 32, got %d", SharedKeySize)
	}
}
