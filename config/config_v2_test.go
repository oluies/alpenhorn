// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

// NOTE: this file lives in package `config`, which transitively imports
// vuvuzela.io/crypto/bls -> bn256. The bn256 package ships hand-rolled
// x86_64-only assembly that does not build on arm64. As a result this
// test cannot be run locally on darwin/arm64; it runs in CI on
// linux/amd64. Test helpers (`newGuardian`, `hybridSign`) live in
// config_test.go and are reused here.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
)

// TestVerifyV2Roundtrip exercises the full happy-path: generate a
// hybrid guardian, build a v2 SignedConfig, sign with both halves,
// confirm Verify accepts. Mirrors TestVerify but only over a single
// config (the chain case is in TestVerify itself, now exercising v2 by
// virtue of newGuardian / hybridSign).
func TestVerifyV2Roundtrip(t *testing.T) {
	g, gPriv := newGuardian("alice")
	conf := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,
		Service:          "Trivial",
		Created:          time.Now(),
		Expires:          time.Now().Add(24 * time.Hour),
		Inner:            trivialInner{},
		Guardians:        []Guardian{g},
		Signatures:       make(map[string][]byte),
	}
	if err := conf.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	conf.Signatures[base32.EncodeToString(g.Key)] = hybridSign(gPriv, conf.SigningMessage())
	if err := conf.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestRejectStrippedPQSignature: take a valid v2 signature, zero out the
// PQ half (the last 3309 bytes), and confirm Verify rejects with an
// error explicitly naming the PQ half. The constitution forbids a
// silent classical-only fallback.
func TestRejectStrippedPQSignature(t *testing.T) {
	g, gPriv := newGuardian("alice")
	conf := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,
		Service:          "Trivial",
		Created:          time.Now(),
		Expires:          time.Now().Add(24 * time.Hour),
		Inner:            trivialInner{},
		Guardians:        []Guardian{g},
		Signatures:       make(map[string][]byte),
	}
	keystr := base32.EncodeToString(g.Key)
	sig := hybridSign(gPriv, conf.SigningMessage())
	// Strip the PQ half by zeroing the last 3309 bytes.
	stripped := append([]byte(nil), sig...)
	for i := HybridSignatureEdSize; i < HybridSignatureSize; i++ {
		stripped[i] = 0
	}
	conf.Signatures[keystr] = stripped
	err := conf.Verify()
	if err == nil {
		t.Fatal("Verify accepted a stripped-PQ signature")
	}
	if !strings.Contains(err.Error(), "ml-dsa-65") && !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("Verify error did not name the PQ half: %v", err)
	}
}

// TestRejectStrippedEdSignature: symmetric to the above for the classical half.
func TestRejectStrippedEdSignature(t *testing.T) {
	g, gPriv := newGuardian("alice")
	conf := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,
		Service:          "Trivial",
		Created:          time.Now(),
		Expires:          time.Now().Add(24 * time.Hour),
		Inner:            trivialInner{},
		Guardians:        []Guardian{g},
		Signatures:       make(map[string][]byte),
	}
	keystr := base32.EncodeToString(g.Key)
	sig := hybridSign(gPriv, conf.SigningMessage())
	stripped := append([]byte(nil), sig...)
	for i := 0; i < HybridSignatureEdSize; i++ {
		stripped[i] = 0
	}
	conf.Signatures[keystr] = stripped
	err := conf.Verify()
	if err == nil {
		t.Fatal("Verify accepted a stripped-Ed signature")
	}
	if !strings.Contains(err.Error(), "ed25519") && !strings.Contains(err.Error(), "classical") {
		t.Fatalf("Verify error did not name the classical half: %v", err)
	}
}

// TestRejectWrongSizeSignature: a Signatures-map value of any size
// other than HybridSignatureSize MUST be rejected.
func TestRejectWrongSizeSignature(t *testing.T) {
	g, _ := newGuardian("alice")
	conf := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,
		Service:          "Trivial",
		Created:          time.Now(),
		Expires:          time.Now().Add(24 * time.Hour),
		Inner:            trivialInner{},
		Guardians:        []Guardian{g},
		Signatures: map[string][]byte{
			// Classical-only 64-byte sig (what a v1 attacker would
			// hope to slip in).
			base32.EncodeToString(g.Key): make([]byte, 64),
		},
	}
	err := conf.Verify()
	if err == nil {
		t.Fatal("Verify accepted a wrong-sized signature")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Fatalf("Verify error did not flag the wrong length: %v", err)
	}
}

// TestValidateRequiresPQKey: a Guardian missing PQKey must fail Validate.
func TestValidateRequiresPQKey(t *testing.T) {
	g, _ := newGuardian("alice")
	g.PQKey = nil
	conf := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,
		Service:          "Trivial",
		Created:          time.Now(),
		Expires:          time.Now().Add(24 * time.Hour),
		Inner:            trivialInner{},
		Guardians:        []Guardian{g},
		Signatures:       make(map[string][]byte),
	}
	err := conf.Validate()
	if err == nil {
		t.Fatal("Validate accepted a guardian missing PQKey")
	}
	if !strings.Contains(err.Error(), "PQ key") {
		t.Fatalf("Validate error did not flag the missing PQ key: %v", err)
	}
}

// TestRejectV1Record: a JSON record with Version=1 (the legacy
// classical-only format) MUST be rejected by UnmarshalJSON on this
// codebase. Constitution Principle V: no silent downgrade.
func TestRejectV1Record(t *testing.T) {
	const v1JSON = `{"Version": 1, "Service": "Trivial"}`
	conf := new(SignedConfig)
	err := json.Unmarshal([]byte(v1JSON), conf)
	if err == nil {
		t.Fatal("UnmarshalJSON accepted a v1 record")
	}
	if !strings.Contains(err.Error(), "v1") {
		t.Fatalf("error did not name v1 rejection: %v", err)
	}
}

// TestRejectUnknownVersion: a JSON record with an unknown version (e.g.
// 99) MUST be rejected.
func TestRejectUnknownVersion(t *testing.T) {
	const unknownJSON = `{"Version": 99, "Service": "Trivial"}`
	conf := new(SignedConfig)
	err := json.Unmarshal([]byte(unknownJSON), conf)
	if err == nil {
		t.Fatal("UnmarshalJSON accepted an unknown-version record")
	}
}

// TestMarshalRejectV1: attempting to emit a SignedConfig with Version=1
// must error (the codebase no longer produces v1 records).
func TestMarshalRejectV1(t *testing.T) {
	conf := &SignedConfig{Version: 1, Service: "Trivial"}
	_, err := json.Marshal(conf)
	if err == nil {
		t.Fatal("MarshalJSON accepted a v1 SignedConfig")
	}
}
