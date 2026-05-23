// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqsig"
)

func TestServer(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "alpenhorn_config_test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	persistPath := filepath.Join(tmpDir, "config-server-state")

	guardian1Public, guardian1Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	// Derive the hybrid identity so the Guardian record carries both
	// halves; v2 Validate rejects records with missing PQKey.
	guardian1ID, err := hybrid.HybridIdentityFromEd25519Seed(guardian1Private.Seed())
	if err != nil {
		t.Fatal(err)
	}

	startingConfig := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,

		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Version: 1,

			Coordinator: CoordinatorConfig{
				Key:     guardian1Public,
				Address: "localhost:1234",
			},
			CDNServer: CDNServerConfig{
				Address: "localhost:8080",
				Key:     guardian1Public,
			},
		},

		Guardians: []Guardian{
			{
				Username: "guardian1",
				Key:      guardian1Public,
				PQKey:    pqsig.PackPublicKey(guardian1ID.PQPub),
			},
		},
	}

	server, err := CreateServer(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetCurrentConfig(startingConfig)
	if err != nil {
		t.Fatal(err)
	}

	server, err = LoadServer(persistPath)
	if err != nil {
		t.Fatal(err)
	}

	_, currHash := server.CurrentConfig("AddFriend")
	if currHash != startingConfig.Hash() {
		t.Fatal("wrong current config hash")
	}

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := http.Serve(listener, server)
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	client := &Client{
		ConfigServerURL: "http://" + listener.Addr().String(),
	}

	newConfig := &SignedConfig{
		Version:          SignedConfigVersion,
		MinClientVersion: SignedConfigVersion,

		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		PrevConfigHash: startingConfig.Hash(),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Version: 1,

			Coordinator: CoordinatorConfig{
				Key:     guardian1Public,
				Address: "localhost:1234",
			},
			CDNServer: CDNServerConfig{
				Address: "localhost:8081",
				Key:     guardian1Public,
			},
		},

		// The same guardian as startingConfig, carried over so the
		// chain-verification path on the server has guardians to check
		// against.
		Guardians: []Guardian{
			{
				Username: "guardian1",
				Key:      guardian1Public,
				PQKey:    pqsig.PackPublicKey(guardian1ID.PQPub),
			},
		},
	}

	{
		// Try uploading a new config without the guardian's signature.
		err := client.SetCurrentConfig(newConfig)
		if err == nil {
			t.Fatal("expecting error")
		}
	}

	// Sign the new config and try again. Hybrid signature: 64 bytes
	// Ed25519 || 3309 bytes ML-DSA-65.
	newConfig.Signatures = make(map[string][]byte)
	gk := base32.EncodeToString(guardian1Public)
	sigEd := ed25519.Sign(guardian1Private, newConfig.SigningMessage())
	sigPQ, err := pqsig.Sign(guardian1ID.PQPriv, newConfig.SigningMessage())
	if err != nil {
		t.Fatal(err)
	}
	var hs HybridSignature
	copy(hs.Ed[:], sigEd)
	copy(hs.PQ[:], sigPQ)
	newConfig.Signatures[gk] = hs.Bytes()

	{
		err := client.SetCurrentConfig(newConfig)
		if err != nil {
			t.Fatal(err)
		}
	}

	{
		conf, err := client.CurrentConfig("AddFriend")
		if err != nil {
			t.Fatal(err)
		}

		if conf.Hash() != newConfig.Hash() {
			t.Fatalf("bad response config: got %q, want %q", conf.Hash(), newConfig.Hash())
		}
	}

	{
		chain, err := client.FetchAndVerifyChain(startingConfig, newConfig.Hash())
		if err != nil {
			t.Fatal(err)
		}

		if chain[0].Hash() != newConfig.Hash() {
			t.Fatal("wrong config in chain")
		}
	}
}
