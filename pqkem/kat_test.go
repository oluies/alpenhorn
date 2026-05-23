// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import (
	"encoding/json"
	"os"
	"testing"
)

// fips203Vectors is the format we expect of testdata/fips203-vectors.json
// when populated with real ACVP-derived vectors. The placeholder file ships
// with an empty Vectors slice; the test skips with a clear message in that
// case so the wider go-test run stays green.
type fips203Vectors struct {
	Status  string            `json:"_status"`
	Vectors []fips203TestCase `json:"vectors"`
}

type fips203TestCase struct {
	Name            string `json:"name"`               // human label
	Kind            string `json:"kind"`               // one of: keyGen, encap, decap, implicitReject
	KeySeed         string `json:"key_seed,omitempty"` // hex, KeySeedSize bytes (keyGen)
	ExpectedPK      string `json:"expected_pk,omitempty"`
	ExpectedSK      string `json:"expected_sk,omitempty"`
	PK              string `json:"pk,omitempty"`         // hex, PublicKeySize bytes (encap)
	EncapSeed       string `json:"encap_seed,omitempty"` // hex, EncapsulationSeedSize bytes (encap)
	ExpectedCT      string `json:"expected_ct,omitempty"`
	ExpectedSS      string `json:"expected_ss,omitempty"`
	SK              string `json:"sk,omitempty"` // hex, PrivateKeySize bytes (decap)
	CT              string `json:"ct,omitempty"` // hex, CiphertextSize bytes (decap or implicitReject)
	ExpectedDecapSS string `json:"expected_decap_ss,omitempty"`
}

// TestACVPKAT walks testdata/fips203-vectors.json and validates each case
// against the CIRCL primitive. The test is the contract entry described in
// contracts/kat-mlkem768.md.
//
// While the vectors file is the shipped placeholder (empty vectors slice
// with _status == "placeholder"), the test skips. The skip is intentional
// and visible — a successful test run does NOT mean the FIPS 203 KAT has
// been validated. The constitution Quality Gate is satisfied only once the
// file holds real ACVP-derived vectors and this test runs against them.
func TestACVPKAT(t *testing.T) {
	data, err := os.ReadFile("testdata/fips203-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v fips203Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Status == "placeholder" || len(v.Vectors) == 0 {
		t.Skipf("testdata/fips203-vectors.json is a placeholder; FIPS 203 KAT not validated. " +
			"Replace with authoritative NIST ACVP-Server vectors before relying on this test.")
	}
	for _, tc := range v.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			runFIPS203Case(t, tc)
		})
	}
}

func runFIPS203Case(t *testing.T, tc fips203TestCase) {
	t.Helper()
	switch tc.Kind {
	case "keyGen":
		seed := mustHex(t, tc.KeySeed)
		pk, sk, err := NewKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("NewKeyFromSeed: %v", err)
		}
		if got, want := PackPublicKey(pk), mustHex(t, tc.ExpectedPK); !bytesEqual(got, want) {
			t.Errorf("public key mismatch")
		}
		if got, want := PackPrivateKey(sk), mustHex(t, tc.ExpectedSK); !bytesEqual(got, want) {
			t.Errorf("private key mismatch")
		}
	case "encap":
		pk, err := UnpackPublicKey(mustHex(t, tc.PK))
		if err != nil {
			t.Fatalf("UnpackPublicKey: %v", err)
		}
		ct, ss, err := EncapsulateDeterministic(pk, mustHex(t, tc.EncapSeed))
		if err != nil {
			t.Fatalf("EncapsulateDeterministic: %v", err)
		}
		if !bytesEqual(ct, mustHex(t, tc.ExpectedCT)) {
			t.Errorf("ciphertext mismatch")
		}
		if !bytesEqual(ss, mustHex(t, tc.ExpectedSS)) {
			t.Errorf("shared secret mismatch")
		}
	case "decap", "implicitReject":
		sk, err := UnpackPrivateKey(mustHex(t, tc.SK))
		if err != nil {
			t.Fatalf("UnpackPrivateKey: %v", err)
		}
		ss, err := Decapsulate(sk, mustHex(t, tc.CT))
		if err != nil {
			t.Fatalf("Decapsulate: %v", err)
		}
		if !bytesEqual(ss, mustHex(t, tc.ExpectedDecapSS)) {
			t.Errorf("decapsulated shared secret mismatch (kind=%s)", tc.Kind)
		}
	default:
		t.Fatalf("unknown KAT kind %q", tc.Kind)
	}
}

// Small local helpers to keep the test file self-contained.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hexDecode(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi, err := hexNibble(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[2*i+1])
		if err != nil {
			return nil, err
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, &hexError{c}
}

type hexError struct{ c byte }

func (e *hexError) Error() string { return "invalid hex byte: " + string(e.c) }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
