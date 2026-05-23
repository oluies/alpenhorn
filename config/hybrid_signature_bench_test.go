// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"testing"
)

func benchmarkSig() HybridSignature {
	var s HybridSignature
	for i := range s.Ed {
		s.Ed[i] = byte(i)
	}
	for i := range s.PQ {
		s.PQ[i] = byte((i * 7) & 0xff)
	}
	return s
}

// BenchmarkHybridSignatureBytes measures the cost of producing the
// canonical concatenated encoding. Should be a single allocation +
// two copies; useful as a lower bound on signed-config encode cost.
func BenchmarkHybridSignatureBytes(b *testing.B) {
	s := benchmarkSig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Bytes()
	}
}

// BenchmarkHybridSignatureUnmarshalBytes measures the cost of decoding
// the canonical concatenated form.
func BenchmarkHybridSignatureUnmarshalBytes(b *testing.B) {
	s := benchmarkSig()
	bytesIn := s.Bytes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var s2 HybridSignature
		if err := s2.UnmarshalBytes(bytesIn); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybridSignatureMarshalJSON includes the base64 encoding
// overhead. Practical encode cost when SignedConfig is serialized for
// transport or CDN distribution.
func BenchmarkHybridSignatureMarshalJSON(b *testing.B) {
	s := benchmarkSig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(&s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybridSignatureUnmarshalJSON measures decode cost including
// base64 decode.
func BenchmarkHybridSignatureUnmarshalJSON(b *testing.B) {
	s := benchmarkSig()
	enc, err := json.Marshal(&s)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var s2 HybridSignature
		if err := json.Unmarshal(enc, &s2); err != nil {
			b.Fatal(err)
		}
	}
}
