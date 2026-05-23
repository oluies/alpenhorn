// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestCIRCLConstantsMatchScheme guards against silent constant drift when
// upgrading CIRCL. FIPS 204 fixes ML-DSA-65 sizes; any drift would be a
// CIRCL bug, but we want to catch it at upgrade time rather than in the
// field.
func TestCIRCLConstantsMatchScheme(t *testing.T) {
	sch := mldsa65.Scheme()
	if got, want := sch.PublicKeySize(), PublicKeySize; got != want {
		t.Errorf("PublicKeySize: pqsig=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.PrivateKeySize(), PrivateKeySize; got != want {
		t.Errorf("PrivateKeySize: pqsig=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.SignatureSize(), SignatureSize; got != want {
		t.Errorf("SignatureSize: pqsig=%d, CIRCL Scheme=%d", want, got)
	}
	if got, want := sch.SeedSize(), SeedSize; got != want {
		t.Errorf("SeedSize: pqsig=%d, CIRCL Scheme=%d", want, got)
	}
	// FIPS 204 mandates 1952 / 4032 / 3309 / 32. Hard-code them as the
	// final backstop.
	if PublicKeySize != 1952 {
		t.Errorf("FIPS 204: PublicKeySize must be 1952, got %d", PublicKeySize)
	}
	if PrivateKeySize != 4032 {
		t.Errorf("FIPS 204: PrivateKeySize must be 4032, got %d", PrivateKeySize)
	}
	if SignatureSize != 3309 {
		t.Errorf("FIPS 204: SignatureSize must be 3309, got %d", SignatureSize)
	}
	if SeedSize != 32 {
		t.Errorf("FIPS 204: SeedSize must be 32, got %d", SeedSize)
	}
}
