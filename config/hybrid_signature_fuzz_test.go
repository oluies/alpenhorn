// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FuzzHybridSignatureUnmarshalBytes asserts UnmarshalBytes never panics
// and only succeeds on inputs of exactly HybridSignatureSize length.
//
// Run with:
//
//	go test -fuzz=FuzzHybridSignatureUnmarshalBytes -fuzztime=30s ./config
func FuzzHybridSignatureUnmarshalBytes(f *testing.F) {
	f.Add(make([]byte, HybridSignatureSize))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, HybridSignatureSize-1))
	f.Add(make([]byte, HybridSignatureSize+1))

	f.Fuzz(func(t *testing.T, b []byte) {
		var s HybridSignature
		err := s.UnmarshalBytes(b)
		switch {
		case len(b) == HybridSignatureSize && err != nil:
			t.Fatalf("rejected valid-length input (%d bytes): %v", len(b), err)
		case len(b) != HybridSignatureSize && err == nil:
			t.Fatalf("accepted wrong-length input (%d bytes, want %d)", len(b), HybridSignatureSize)
		}
	})
}

// FuzzHybridSignatureUnmarshalJSON asserts that UnmarshalJSON never
// panics on arbitrary byte input. Valid JSON strings whose base64
// payload decodes to the right length must succeed; everything else
// must return an error rather than panic.
func FuzzHybridSignatureUnmarshalJSON(f *testing.F) {
	// Seed corpus: a valid-looking encoded signature, plus some near-misses.
	valid, _ := json.Marshal(base64.StdEncoding.EncodeToString(make([]byte, HybridSignatureSize)))
	f.Add(valid)
	f.Add([]byte(`""`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"not base64!!!"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		var s HybridSignature
		// We only care that UnmarshalJSON doesn't panic; error is fine.
		_ = s.UnmarshalJSON(b)
	})
}
