// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestHybridSignatureRoundtripBytes(t *testing.T) {
	var s HybridSignature
	for i := range s.Ed {
		s.Ed[i] = byte(i)
	}
	for i := range s.PQ {
		s.PQ[i] = byte((i * 7) & 0xff)
	}
	b := s.Bytes()
	if len(b) != HybridSignatureSize {
		t.Fatalf("Bytes length = %d, want %d", len(b), HybridSignatureSize)
	}
	var s2 HybridSignature
	if err := s2.UnmarshalBytes(b); err != nil {
		t.Fatalf("UnmarshalBytes: %v", err)
	}
	if !bytes.Equal(s.Ed[:], s2.Ed[:]) {
		t.Fatal("Ed half differs after round-trip")
	}
	if !bytes.Equal(s.PQ[:], s2.PQ[:]) {
		t.Fatal("PQ half differs after round-trip")
	}
}

func TestHybridSignatureRoundtripJSON(t *testing.T) {
	var s HybridSignature
	for i := range s.Ed {
		s.Ed[i] = byte(i * 3)
	}
	for i := range s.PQ {
		s.PQ[i] = byte((i * 5) & 0xff)
	}
	enc, err := json.Marshal(&s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var s2 HybridSignature
	if err := json.Unmarshal(enc, &s2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(s.Ed[:], s2.Ed[:]) {
		t.Fatal("Ed half differs after JSON round-trip")
	}
	if !bytes.Equal(s.PQ[:], s2.PQ[:]) {
		t.Fatal("PQ half differs after JSON round-trip")
	}
}

func TestHybridSignatureRejectsWrongSize(t *testing.T) {
	var s HybridSignature
	err := s.UnmarshalBytes(make([]byte, 1))
	if !errors.Is(err, ErrHybridSignatureSize) {
		t.Fatalf("UnmarshalBytes(short): want ErrHybridSignatureSize, got %v", err)
	}
	err = s.UnmarshalBytes(make([]byte, HybridSignatureSize+1))
	if !errors.Is(err, ErrHybridSignatureSize) {
		t.Fatalf("UnmarshalBytes(long): want ErrHybridSignatureSize, got %v", err)
	}
}
