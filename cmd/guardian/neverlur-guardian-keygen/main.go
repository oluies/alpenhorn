// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/oluies/neverlur/cmd/guardian"
	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqsig"
)

var hybridOutFlag = flag.String("hybrid-out", "",
	"Optional path to write a .neverlur-id-v2 hybrid identity file alongside the legacy guardian key files. "+
		"The v2 file carries the Ed25519 seed in PLAINTEXT (mode 0600); supply only on hosts where that risk profile is acceptable. "+
		"The hybrid post-quantum (ML-DSA-65) half is derived from the same Ed25519 seed via the R4 binding.")

var inspirationalMessage = `
!! You are generating an Alpenhorn guardian key.
!! This key is crucial to the security of Alpenhorn.
!! Millions of users are counting on you. Pick a STRONG passphrase.

`

func main() {
	flag.Parse()

	appDir := guardian.Appdir()
	err := os.Mkdir(appDir, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", appDir)
	} else if !os.IsExist(err) {
		log.Fatal(err)
	}

	privatePath := filepath.Join(appDir, "guardian.privatekey")
	publicPath := filepath.Join(appDir, "guardian.publickey")
	checkOverwrite(privatePath)
	checkOverwrite(publicPath)
	if *hybridOutFlag != "" {
		checkOverwrite(*hybridOutFlag)
	}

	_, _ = fmt.Fprint(os.Stdout, inspirationalMessage)
	pw := confirmPassphrase()
	fmt.Println()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dk := guardian.DeriveKey(pw)
	var boxKey [32]byte
	copy(boxKey[:], dk)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		panic(err)
	}
	msg := privateKey[:]
	ctxt := secretbox.Seal(nonce[:], msg, &nonce, &boxKey)

	err = ioutil.WriteFile(publicPath, []byte(base32.EncodeToString(publicKey[:])+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write public key: %s", err)
	}
	fmt.Printf("Wrote public key: %s\n", publicPath)

	err = ioutil.WriteFile(privatePath, []byte(base32.EncodeToString(ctxt)+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write private key: %s", err)
	}
	fmt.Printf("Wrote private key: %s\n", privatePath)

	if *hybridOutFlag != "" {
		id, err := hybrid.HybridIdentityFromEd25519Seed(privateKey.Seed())
		if err != nil {
			log.Fatalf("failed to derive hybrid identity: %s", err)
		}
		if err := hybrid.WriteIdentityFile(*hybridOutFlag, id); err != nil {
			log.Fatalf("failed to write hybrid identity file: %s", err)
		}
		pqPubBytes := pqsig.PackPublicKey(id.PQPub)
		fmt.Printf("Wrote hybrid identity file: %s\n", *hybridOutFlag)
		fmt.Printf("  ml-dsa-65 public key (base32, %d bytes): %s\n", len(pqPubBytes), base32.EncodeToString(pqPubBytes))
	}

	fmt.Printf("\n!! You should make a backup of the private key before sharing the public key.\n")
}

func confirmPassphrase() []byte {
	for {
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
		pw, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if len(pw) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
		again, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if bytes.Equal(pw, again) {
			return pw
		}

		fmt.Fprintf(os.Stderr, "Passphrases do not match. Try again.\n")
	}
}

func checkOverwrite(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s already exists. Refusing to overwrite.\n", path)
	os.Exit(1)
}
