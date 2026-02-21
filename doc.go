// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

/*
Package bisign implements Bohemia Interactive signature and key file formats
used by Arma and DayZ (.biprivatekey, .bikey, .bisign).

# Key files

Load and write RSA keys in BI format:

	priv, err := bisign.LoadPrivate("identity.biprivatekey")
	if err != nil { ... }
	pub := priv.Public()
	bisign.WritePublic("identity.bikey", pub)

Generate a new key pair:

	priv, err := bisign.Generate("mykey", 1024)
	bisign.WritePrivate("mykey.biprivatekey", priv)
	bisign.WritePublic("mykey.bikey", priv.Public())

# Signatures

Sign a hash set (e.g. from PBO hashes) and write a .bisign file:

	var hs bisign.HashSet
	// fill hs.Hash1, Hash2, Hash3 with 20-byte SHA1 digests
	sig, err := priv.SignHashes(bisign.Version3, hs)
	bisign.WriteSignature("file.pbo.mykey.bisign", sig)

Load a .bisign and recover or verify hashes:

	s, err := bisign.LoadSignature("file.pbo.mykey.bisign")
	recovered, err := s.RecoverHashes()
	err = s.VerifyHashes(expectedHashSet)

Inspect metadata from one supported file type:

	info, err := bisign.Inspect("identity.bikey")
	_ = info

Only bisign versions 2 and 3 are supported. Signing uses PKCS#1 v1.5 with
SHA-1. Generate accepts power-of-two key sizes starting at 512 bits. BI files
can be loaded/saved via paths, readers/writers, or in-memory bytes.
*/
package bisign
