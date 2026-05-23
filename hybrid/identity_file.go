// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// IdentityFileVersion is the on-disk schema version this code reads and
// writes. Bumping this constant is a wire-incompatible change for the
// identity file format only (network artifacts are unaffected).
const IdentityFileVersion = 2

// IdentityFileSuffix is appended to operator-chosen identity-file names
// to mark them as the v2 hybrid format.
const IdentityFileSuffix = ".neverlur-id-v2"

// identityFileMode is the required permission mode for an identity file.
// Anything broader than 0600 is refused on load.
const identityFileMode = 0o600

// IdentityFile is the on-disk representation of a HybridIdentity.
// See data-model.md E2 and research.md R9.
type IdentityFile struct {
	Version     int       `json:"version"`
	Ed25519Seed []byte    `json:"ed25519_seed"` // 32 bytes
	MLDSA65Seed []byte    `json:"mldsa65_seed"` // 32 bytes; MUST satisfy R4 binding
	Created     time.Time `json:"created"`
	RotatedFrom *string   `json:"rotated_from,omitempty"`
}

// ErrIdentityFileUnreadable indicates the file mode is broader than 0600.
var ErrIdentityFileUnreadable = errors.New("hybrid: identity file mode too permissive; expect 0600")

// LoadIdentityFile reads a v2 identity file from path, re-verifies the
// R4 binding, and returns the resulting in-memory HybridIdentity.
func LoadIdentityFile(path string) (*HybridIdentity, error) {
	if err := checkSecurePerms(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hybrid: read identity file: %w", err)
	}
	var f IdentityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("hybrid: parse identity file: %w", err)
	}
	if f.Version != IdentityFileVersion {
		return nil, fmt.Errorf("hybrid: identity file version %d, want %d", f.Version, IdentityFileVersion)
	}
	if len(f.Ed25519Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hybrid: ed25519 seed length %d, want %d", len(f.Ed25519Seed), ed25519.SeedSize)
	}
	id, err := HybridIdentityFromEd25519Seed(f.Ed25519Seed)
	if err != nil {
		return nil, err
	}
	id.Created = f.Created
	// Sanity: the persisted MLDSA65Seed (if present) must match the
	// derived one. If it does not, the file is internally inconsistent
	// and we refuse to load rather than silently disagree with the disk.
	if len(f.MLDSA65Seed) != 0 {
		// We don't store the derived seed on disk independently of the
		// derivation; we re-derive on load. So check the persisted bytes
		// match the derivation. If they do not, the file is hand-edited.
		derived, err := deriveMLDSASeedBytes(f.Ed25519Seed)
		if err != nil {
			return nil, err
		}
		if !bytesEqualConst(derived, f.MLDSA65Seed) {
			return nil, ErrBindingFailed
		}
	}
	if err := id.VerifyBinding(); err != nil {
		return nil, err
	}
	return id, nil
}

// WriteIdentityFile writes id to path as a v2 identity file with mode 0600.
// Refuses to overwrite an existing file (use a fresh path for rotation).
func WriteIdentityFile(path string, id *HybridIdentity) error {
	if id == nil || id.EdPriv == nil {
		return ErrIdentityIncomplete
	}
	edSeed := id.EdPriv.Seed()
	mldsaSeed, err := deriveMLDSASeedBytes(edSeed)
	if err != nil {
		return err
	}
	f := IdentityFile{
		Version:     IdentityFileVersion,
		Ed25519Seed: edSeed,
		MLDSA65Seed: mldsaSeed,
		Created:     id.Created,
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("hybrid: marshal identity file: %w", err)
	}
	// O_EXCL refuses to overwrite an existing file.
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, identityFileMode)
	if err != nil {
		return fmt.Errorf("hybrid: create identity file: %w", err)
	}
	defer out.Close()
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("hybrid: write identity file: %w", err)
	}
	return nil
}

// LoadOrUpgradeIdentityFile loads a hybrid identity file, or upgrades a
// legacy single-key Ed25519 file in place per research.md R9.
//
// If `<basename>.neverlur-id-v2` exists, it is loaded directly.
// Otherwise, if `legacyPath` exists and contains a 32-byte Ed25519 seed,
// a fresh v2 file is written next to it (named `<basename>.neverlur-id-v2`)
// and that file is loaded. The legacy file is left in place for rollback.
//
// `legacyPath` may be empty if no legacy file is expected; in that case
// only the v2 path is attempted.
//
// The returned `upgraded` is true iff this call produced a new v2 file
// from a legacy one.
func LoadOrUpgradeIdentityFile(v2Path, legacyPath string) (id *HybridIdentity, upgraded bool, err error) {
	if _, statErr := os.Stat(v2Path); statErr == nil {
		id, err = LoadIdentityFile(v2Path)
		return id, false, err
	}
	if legacyPath == "" {
		return nil, false, fmt.Errorf("hybrid: no identity file at %q and no legacy path provided", v2Path)
	}
	if err := checkSecurePerms(legacyPath); err != nil {
		return nil, false, err
	}
	legacy, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil, false, fmt.Errorf("hybrid: read legacy identity: %w", err)
	}
	if len(legacy) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("hybrid: legacy file length %d, want %d (raw ed25519 seed)", len(legacy), ed25519.SeedSize)
	}
	id, err = HybridIdentityFromEd25519Seed(legacy)
	if err != nil {
		return nil, false, err
	}
	if err := WriteIdentityFile(v2Path, id); err != nil {
		return nil, false, fmt.Errorf("hybrid: persist upgraded identity: %w", err)
	}
	return id, true, nil
}

// DefaultV2Path returns the canonical hybrid identity file path for a
// given legacy file path: same directory, same basename, with the v2
// suffix appended.
func DefaultV2Path(legacyPath string) string {
	dir := filepath.Dir(legacyPath)
	base := filepath.Base(legacyPath)
	return filepath.Join(dir, base+IdentityFileSuffix)
}

func checkSecurePerms(path string) error {
	// File-mode bits are not meaningful on Windows in the same way.
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("hybrid: stat identity file: %w", err)
	}
	mode := st.Mode().Perm()
	// Refuse anything that grants read or write to group or other.
	if mode&0o077 != 0 {
		return fmt.Errorf("%w: file %s has mode %#o", ErrIdentityFileUnreadable, path, mode)
	}
	return nil
}

// deriveMLDSASeedBytes re-runs the HKDF derivation used by pqsig and
// returns the 32-byte ML-DSA-65 seed. Kept here (rather than exposed
// from pqsig) so the identity file's internal-consistency check stays a
// local invariant rather than a public API.
func deriveMLDSASeedBytes(edSeed []byte) ([]byte, error) {
	// We derive via the same code path as DeriveFromEd25519Seed but only
	// need the seed, not the keypair. Re-importing the HKDF logic here
	// would duplicate it; instead derive the keypair and return its seed
	// via the underlying CIRCL API.
	_, sk, err := pqsigDeriveSeedOnly(edSeed)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
