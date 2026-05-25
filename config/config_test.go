// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"github.com/oluies/neverlur/debug"
	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pkg"
	"github.com/oluies/neverlur/pqsig"
	"github.com/oluies/neverlur/mixnet"
)

type trivialInner struct{}

func (x trivialInner) Validate() error   { return nil }
func (x trivialInner) UseLatestVersion() {}

func TestVerify(t *testing.T) {
	gA, gApriv := newGuardian("A")

	conf1 := &SignedConfig{
		Version:    SignedConfigVersion,
		Service:    "Trivial",
		Created:    time.Now(),
		Expires:    time.Now().Add(24 * time.Hour),
		Inner:      trivialInner{},
		Guardians:  []Guardian{gA},
		Signatures: make(map[string][]byte),
	}

	if err := conf1.Validate(); err != nil {
		t.Fatal(err)
	}
	err := conf1.Verify()
	if err == nil {
		t.Fatal("expecting Verify to fail")
	}

	conf1.Signatures[base32.EncodeToString(gA.Key)] = hybridSign(gApriv, conf1.SigningMessage())

	err = conf1.Verify()
	if err != nil {
		t.Fatal(err)
	}

	gB, gBpriv := newGuardian("B")

	conf2 := &SignedConfig{
		Version:        SignedConfigVersion,
		Service:        "Trivial",
		Created:        time.Now(),
		Expires:        time.Now().Add(24 * time.Hour),
		PrevConfigHash: conf1.Hash(),
		Inner:          trivialInner{},
		Guardians:      []Guardian{gB},
		Signatures:     nil,
	}

	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gA.Key): hybridSign(gApriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}
	err = conf2.Verify()
	if err == nil {
		t.Fatal("expecting Verify to fail")
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gB.Key): hybridSign(gBpriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}
	err = conf2.Verify()
	if err != nil {
		t.Fatal(err)
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gA.Key): hybridSign(gApriv, conf2.SigningMessage()),
		base32.EncodeToString(gB.Key): hybridSign(gBpriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err != nil {
		t.Fatal(err)
	}
	err = conf2.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

// newGuardian generates a hybrid identity (R4-bound) and returns the
// Guardian record (with both Ed25519 and ML-DSA-65 public keys filled
// in) along with the Ed25519 private key for inline signing in tests.
// The post-quantum private half can be re-derived from the Ed25519
// seed by hybridSign below.
func newGuardian(username string) (Guardian, ed25519.PrivateKey) {
	_, guardianPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	id, err := hybrid.HybridIdentityFromEd25519Seed(guardianPriv.Seed())
	if err != nil {
		panic(err)
	}
	return Guardian{
		Username: username,
		Key:      id.EdPub,
		PQKey:    pqsig.PackPublicKey(id.PQPub),
	}, guardianPriv
}

// hybridSign produces a v2-format HybridSignature blob (Ed25519 || ML-DSA-65,
// 3373 bytes total) over msg, suitable for storing in
// SignedConfig.Signatures. The PQ private half is re-derived from the
// Ed25519 seed on every call — fine for test code, where the cost is
// dominated by the actual ML-DSA-65 sign anyway.
func hybridSign(edPriv ed25519.PrivateKey, msg []byte) []byte {
	id, err := hybrid.HybridIdentityFromEd25519Seed(edPriv.Seed())
	if err != nil {
		panic(err)
	}
	sigEd := ed25519.Sign(edPriv, msg)
	sigPQ, err := pqsig.Sign(id.PQPriv, msg)
	if err != nil {
		panic(err)
	}
	var hs HybridSignature
	copy(hs.Ed[:], sigEd)
	copy(hs.PQ[:], sigPQ)
	return hs.Bytes()
}

func TestMarshalAddFriendConfig(t *testing.T) {
	guardian, guardianPriv := newGuardian("david")
	guardianPub := guardian.Key

	conf := &SignedConfig{
		Version: SignedConfigVersion,

		// UTC strips the *time.Location pointer (defaults to time.Local,
		// which reflect.DeepEqual treats as different from the fixed-zone
		// Location that JSON round-tripping produces). Round(0) drops the
		// monotonic clock.
		Created: time.Now().UTC().Round(0),
		Expires: time.Now().UTC().Round(0),

		Guardians: []Guardian{guardian},

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Version: AddFriendConfigVersion,

			Coordinator: CoordinatorConfig{
				Key:     guardianPub,
				Address: "localhost:8080",
			},
			MixServers: []mixnet.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:1234",
				},
			},
			PKGServers: []pkg.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:5678",
				},
			},
			CDNServer: CDNServerConfig{
				Key:     guardianPub,
				Address: "localhost:8888",
			},
			Registrar: RegistrarConfig{
				Key:     guardianPub,
				Address: "vuvuzela.io",
			},
		},
	}
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(guardianPub): hybridSign(guardianPriv, conf.SigningMessage()),
	}
	if err := conf.Verify(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	/*
		buf := new(bytes.Buffer)
		err = json.Indent(buf, data, "  ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Marshaled config:\n%s\n", buf.Bytes())
	*/

	conf2 := new(SignedConfig)
	err = json.Unmarshal(data, conf2)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Hash() != conf2.Hash() {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
	if !reflect.DeepEqual(conf, conf2) {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
}

func TestMarshalDialingConfig(t *testing.T) {
	guardian, guardianPriv := newGuardian("david")
	guardianPub := guardian.Key

	conf := &SignedConfig{
		Version: SignedConfigVersion,

		// UTC strips the *time.Location pointer (defaults to time.Local,
		// which reflect.DeepEqual treats as different from the fixed-zone
		// Location that JSON round-tripping produces). Round(0) drops the
		// monotonic clock.
		Created: time.Now().UTC().Round(0),
		Expires: time.Now().UTC().Round(0),

		Guardians: []Guardian{guardian},

		Service: "Dialing",
		Inner: &DialingConfig{
			Version: DialingConfigVersion,

			Coordinator: CoordinatorConfig{
				Key:     guardianPub,
				Address: "localhost:8080",
			},
			MixServers: []mixnet.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:1234",
				},
			},
			CDNServer: CDNServerConfig{
				Key:     guardianPub,
				Address: "localhost:8888",
			},
		},
	}
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(guardianPub): hybridSign(guardianPriv, conf.SigningMessage()),
	}
	if err := conf.Verify(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}

	conf2 := new(SignedConfig)
	err = json.Unmarshal(data, conf2)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Hash() != conf2.Hash() {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
	if !reflect.DeepEqual(conf, conf2) {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
}

const exampleConfig = `
{
  "Version": 1,
  "Service": "AddFriend",
  "Created": "2017-09-29T06:47:05.396965796-04:00",
  "Expires": "2017-09-29T06:47:05.396966008-04:00",
  "PrevConfigHash": "",
  "Inner": {
    "Version": 1,
    "Coordinator": {
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
      "Address": "localhost:8080"
    },
    "PKGServers": [
      {
        "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
        "Address": "localhost:5678"
      }
    ],
    "MixServers": [
      {
        "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
        "Address": "localhost:1234"
      }
    ],
    "CDNServer": {
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
      "Address": "localhost:8888"
	},
	"RegistrarHost": "vuvuzela.io"
  },
  "Guardians": [
    {
      "Username": "david",
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0"
    }
  ],
  "Signatures": {
    "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0": "6k9nkf4exwd1r1yhc00b0r8ky4y9006svj2n06w4bd3t226rxfrdn6mbt07rp5r6sw8mfy67y00z06k2tnd4sga4325pk3p5gzx862r"
  }
}
`

// TestUnmarshalConfig asserts that the v2 codebase REJECTS legacy v1
// JSON records outright (no silent downgrade — constitution Principle V,
// docs/wire-signed-config-v2.md). The exampleConfig string above is the
// historical v1 sample preserved for documentation; v2 codebases see it
// and refuse to parse, returning an error that explicitly cites the
// design note.
func TestUnmarshalConfig(t *testing.T) {
	conf := new(SignedConfig)
	err := json.Unmarshal([]byte(exampleConfig), conf)
	if err == nil {
		t.Fatalf("expected v1 record to be rejected; got nil error and parsed conf=%s", debug.Pretty(conf))
	}
}
