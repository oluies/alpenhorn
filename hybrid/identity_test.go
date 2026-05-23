// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oluies/neverlur/pqsig"
)

func TestGenerateAndPersistIdentity(t *testing.T) {
	id, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("GenerateHybridIdentity: %v", err)
	}
	if err := id.VerifyBinding(); err != nil {
		t.Fatalf("VerifyBinding on fresh identity: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "alice"+IdentityFileSuffix)
	if err := WriteIdentityFile(path, id); err != nil {
		t.Fatalf("WriteIdentityFile: %v", err)
	}
	id2, err := LoadIdentityFile(path)
	if err != nil {
		t.Fatalf("LoadIdentityFile: %v", err)
	}
	if !bytes.Equal(id.EdPub, id2.EdPub) {
		t.Fatal("Ed25519 public key mismatch after persistence")
	}
	if !bytes.Equal(pqsig.PackPublicKey(id.PQPub), pqsig.PackPublicKey(id2.PQPub)) {
		t.Fatal("ML-DSA-65 public key mismatch after persistence")
	}
}

func TestLoadRejectsBadBinding(t *testing.T) {
	id, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("GenerateHybridIdentity: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "alice"+IdentityFileSuffix)
	if err := WriteIdentityFile(path, id); err != nil {
		t.Fatalf("WriteIdentityFile: %v", err)
	}
	// Hand-edit: tamper with the persisted MLDSA seed so it no longer
	// matches the derivation from the Ed25519 seed. The loader's
	// internal-consistency check must catch this.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f IdentityFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Flip one bit of the persisted MLDSA seed.
	f.MLDSA65Seed = append([]byte(nil), f.MLDSA65Seed...)
	f.MLDSA65Seed[0] ^= 0x01
	data2, _ := json.MarshalIndent(&f, "", "  ")
	if err := os.WriteFile(path, data2, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	_, err = LoadIdentityFile(path)
	if !errors.Is(err, ErrBindingFailed) {
		t.Fatalf("want ErrBindingFailed, got %v", err)
	}
}

func TestUpgradeV1FileInPlace(t *testing.T) {
	dir := t.TempDir()
	// Simulate a legacy file: raw 32-byte Ed25519 seed.
	legacy := filepath.Join(dir, "alice.id")
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	if err := os.WriteFile(legacy, seed, 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	v2 := DefaultV2Path(legacy)
	id, upgraded, err := LoadOrUpgradeIdentityFile(v2, legacy)
	if err != nil {
		t.Fatalf("LoadOrUpgradeIdentityFile: %v", err)
	}
	if !upgraded {
		t.Fatal("expected upgraded=true on first run")
	}
	if id == nil {
		t.Fatal("nil identity returned")
	}
	if err := id.VerifyBinding(); err != nil {
		t.Fatalf("VerifyBinding on upgraded identity: %v", err)
	}
	// The legacy file must still be present (rollback path).
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy file removed: %v", err)
	}
	// The v2 file must now exist.
	if _, err := os.Stat(v2); err != nil {
		t.Fatalf("v2 file not written: %v", err)
	}
	// A second call must load the v2 file directly without "upgrading".
	id2, upgraded2, err := LoadOrUpgradeIdentityFile(v2, legacy)
	if err != nil {
		t.Fatalf("second LoadOrUpgradeIdentityFile: %v", err)
	}
	if upgraded2 {
		t.Fatal("second call reported upgraded=true; expected false")
	}
	if !bytes.Equal(id.EdPub, id2.EdPub) {
		t.Fatal("Ed25519 pub mismatch between upgrade and reload")
	}
}

func TestRefuseGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode checks not enforced on Windows")
	}
	id, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("GenerateHybridIdentity: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "alice"+IdentityFileSuffix)
	if err := WriteIdentityFile(path, id); err != nil {
		t.Fatalf("WriteIdentityFile: %v", err)
	}
	// Loosen the mode and confirm load refuses.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err = LoadIdentityFile(path)
	if !errors.Is(err, ErrIdentityFileUnreadable) {
		t.Fatalf("want ErrIdentityFileUnreadable, got %v", err)
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	id, _ := GenerateHybridIdentity()
	dir := t.TempDir()
	path := filepath.Join(dir, "alice"+IdentityFileSuffix)
	if err := WriteIdentityFile(path, id); err != nil {
		t.Fatalf("first write: %v", err)
	}
	err := WriteIdentityFile(path, id)
	if err == nil {
		t.Fatal("expected overwrite refusal, got nil")
	}
}

func TestHybridIdentityFromEd25519SeedDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	id1, err := HybridIdentityFromEd25519Seed(seed)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	id2, err := HybridIdentityFromEd25519Seed(seed)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(id1.EdPub, id2.EdPub) {
		t.Fatal("Ed25519 public key changed across calls with same seed")
	}
	if !bytes.Equal(pqsig.PackPublicKey(id1.PQPub), pqsig.PackPublicKey(id2.PQPub)) {
		t.Fatal("ML-DSA-65 public key changed across calls with same seed")
	}
}

func TestHybridIdentityPublicEqual(t *testing.T) {
	id1, _ := GenerateHybridIdentity()
	id2, _ := GenerateHybridIdentity()
	if !id1.Public().Equal(id1.Public()) {
		t.Fatal("identity is not equal to itself")
	}
	if id1.Public().Equal(id2.Public()) {
		t.Fatal("two distinct identities reported equal")
	}
	if (*HybridIdentityPublic)(nil).Equal(id1.Public()) {
		t.Fatal("nil equality should be false")
	}
}
