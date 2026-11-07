// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

/*
Package bisign reads, writes, creates, and verifies
BI key and signature files used by Arma and DayZ:
`.bikey`, `.biprivatekey`, and `.bisign`.

Callers provide the three digests in [HashSet].
The package does not read PBO files or calculate their hashes.
Signing uses PKCS#1 v1.5 with SHA-1 and creates V2 or V3 signatures.

[SignatureFile.VerifyHashes] checks only the block selected by the signature version:
V1 uses [HashSet.Hash1], V2 uses [HashSet.Hash2], and V3 uses [HashSet.Hash3].
[SignatureFile.RecoverHashes] attempts all three blocks and may fail on an unselected block.
Parsing checks the BI structure, not the signature's cryptographic validity.

Runnable examples for key creation, signing and verification,
and metadata inspection appear in the Go package documentation.
*/
package bisign
