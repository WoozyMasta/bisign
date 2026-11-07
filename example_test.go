// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/woozymasta/bisign"
)

// ExampleGenerate creates a BI key pair and reloads both files.
func ExampleGenerate() {
	dir, err := os.MkdirTemp("", "bisign-example-")
	if err != nil {
		fmt.Println("create temporary directory:", err)
		return
	}
	defer os.RemoveAll(dir)

	private, err := bisign.Generate("example-key", 2048)
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}

	privatePath := filepath.Join(dir, "example-key.biprivatekey")
	publicPath := filepath.Join(dir, "example-key.bikey")
	if err := bisign.WritePrivate(privatePath, private); err != nil {
		fmt.Println("write private key:", err)
		return
	}
	if err := bisign.WritePublic(publicPath, private.Public()); err != nil {
		fmt.Println("write public key:", err)
		return
	}

	loadedPrivate, err := bisign.LoadPrivate(privatePath)
	if err != nil {
		fmt.Println("load private key:", err)
		return
	}
	loadedPublic, err := bisign.LoadPublic(publicPath)
	if err != nil {
		fmt.Println("load public key:", err)
		return
	}

	fmt.Printf(
		"%s: %d-bit RSA; public key matches=%t\n",
		loadedPrivate.Name,
		loadedPrivate.Key.N.BitLen(),
		bisign.PublicEqual(&loadedPrivate.Key.PublicKey, loadedPublic.Key),
	)
	// Output:
	// example-key: 2048-bit RSA; public key matches=true
}

// ExamplePrivateKeyFile_SignHashes signs supplied digests and verifies the BI signature.
func ExamplePrivateKeyFile_SignHashes() {
	private, err := bisign.Generate("example-key", 2048)
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}

	// These fixed-width values stand in for SHA-1 digests computed by the caller.
	hashes := bisign.HashSet{
		Hash1: [20]byte{0x01},
		Hash2: [20]byte{0x02},
		Hash3: [20]byte{0x03},
	}

	signature, err := private.SignHashes(bisign.Version3, hashes)
	if err != nil {
		fmt.Println("sign hashes:", err)
		return
	}

	encoded, err := bisign.MarshalSignature(signature)
	if err != nil {
		fmt.Println("marshal signature:", err)
		return
	}
	loaded, err := bisign.ParseSignature(encoded)
	if err != nil {
		fmt.Println("parse signature:", err)
		return
	}
	if err := loaded.VerifyHashes(hashes); err != nil {
		fmt.Println("verify signature:", err)
		return
	}

	fmt.Printf("version %d verified\n", loaded.Version)
	// Output:
	// version 3 verified
}

// ExampleInspect reads the public-key metadata from a BI key file.
func ExampleInspect() {
	dir, err := os.MkdirTemp("", "bisign-inspect-example-")
	if err != nil {
		fmt.Println("create temporary directory:", err)
		return
	}
	defer os.RemoveAll(dir)

	private, err := bisign.Generate("example-key", 2048)
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}
	path := filepath.Join(dir, "example-key.bikey")
	if err := bisign.WritePublic(path, private.Public()); err != nil {
		fmt.Println("write public key:", err)
		return
	}

	info, err := bisign.Inspect(path)
	if err != nil {
		fmt.Println("inspect key:", err)
		return
	}
	fmt.Printf("%s: %s, %d-bit RSA\n", info.Key.Kind, info.Key.Name, info.Key.RSABits)
	// Output:
	// bikey: example-key, 2048-bit RSA
}
