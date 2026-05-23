// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"github.com/oluies/neverlur/cmd/guardian"
	"github.com/oluies/neverlur/config"
	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/log"
	"github.com/oluies/neverlur/pqsig"

	// Register the convo inner config.
	_ "vuvuzela.io/vuvuzela/convo"
)

var configPath = flag.String("config", "", "path to new signed config")

func main() {
	flag.Parse()

	if *configPath == "" {
		fmt.Println("Specify config file with -config.")
		os.Exit(1)
	}

	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(config.SignedConfig)

	if err := json.Unmarshal(configBytes, conf); err != nil {
		log.Fatalf("error decoding json: %s", err)
	}
	if err := conf.Validate(); err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	appDir := guardian.Appdir()
	privatePath := filepath.Join(appDir, "guardian.privatekey")

	privateKey := guardian.ReadPrivateKey(privatePath)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Derive the hybrid identity (R4 binding) from the Ed25519 seed.
	// This costs ~92us at startup; cheap relative to the sign call.
	id, err := hybrid.HybridIdentityFromEd25519Seed(privateKey.Seed())
	if err != nil {
		log.Fatalf("derive hybrid identity: %s", err)
	}

	myPos := -1
	for i, g := range conf.Guardians {
		if bytes.Equal(g.Key, publicKey) {
			myPos = i
		}
	}
	if myPos == -1 {
		fmt.Fprintf(os.Stderr, "! Warning: your key is not in the supplied config's Guardian list!\n")
	}

	msg := conf.SigningMessage()

	// Hybrid signature: Ed25519 || ML-DSA-65.
	sigEd := ed25519.Sign(privateKey, msg)
	sigPQ, err := pqsig.Sign(id.PQPriv, msg)
	if err != nil {
		log.Fatalf("ml-dsa-65 sign: %s", err)
	}
	var hs config.HybridSignature
	copy(hs.Ed[:], sigEd)
	copy(hs.PQ[:], sigPQ)

	if conf.Signatures == nil {
		conf.Signatures = make(map[string][]byte)
	}
	conf.Signatures[base32.EncodeToString(publicKey)] = hs.Bytes()

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", data)
}
