// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import "errors"

// Sentinel errors for bisign operations.
var (
	// ErrInvalidKeyHeader means the key header is invalid.
	ErrInvalidKeyHeader = errors.New("invalid key header")
	// ErrInvalidKeyTag means the key tag is invalid.
	ErrInvalidKeyTag = errors.New("invalid key tag")
	// ErrBlockSizeMismatch means the block size mismatch.
	ErrBlockSizeMismatch = errors.New("block size mismatch")
	// ErrInvalidPublicKey means the RSA public key data is invalid.
	ErrInvalidPublicKey = errors.New("invalid RSA public key data")
	// ErrInvalidPrivateKey means the RSA private key data is invalid.
	ErrInvalidPrivateKey = errors.New("invalid RSA private key data")
	// ErrUnsupportedVersion means the bisign version is unsupported.
	ErrUnsupportedVersion = errors.New("unsupported bisign version")
	// ErrSignatureSize means the signature size mismatch.
	ErrSignatureSize = errors.New("signature size mismatch")
	// ErrVerifyFailed means the signature verification failed.
	ErrVerifyFailed = errors.New("signature verification failed")
	// ErrUnsupportedPublicSource means the public source is unsupported.
	ErrUnsupportedPublicSource = errors.New("unsupported public source")
	// ErrPrivateKeyNil means the private key is nil.
	ErrPrivateKeyNil = errors.New("private key is nil")
	// ErrPublicKeyNil means the public key is nil.
	ErrPublicKeyNil = errors.New("public key is nil")
	// ErrSignatureNil means the signature file is nil.
	ErrSignatureNil = errors.New("signature file is nil")
	// ErrMissingPublicKey means the public key is missing.
	ErrMissingPublicKey = errors.New("missing public key")
	// ErrMissingPrivateKey means the private key is missing.
	ErrMissingPrivateKey = errors.New("missing private key")
	// ErrMissingEmbeddedPubKey means the signature does not contain an embedded public key.
	ErrMissingEmbeddedPubKey = errors.New("signature does not contain an embedded public key")
	// ErrPublicFromPrivateNil means the private key does not contain a valid public key.
	ErrPublicFromPrivateNil = errors.New("private key does not contain a valid public key")
	// ErrPublicOpNilPublicKey means the public key is nil.
	ErrPublicOpNilPublicKey = errors.New("nil public key")
	// ErrInvalidSignatureInt means the signature integer is invalid.
	ErrInvalidSignatureInt = errors.New("invalid signature integer")
	// ErrPKCS1v15Unpad means the PKCS1v15 unpad failed.
	ErrPKCS1v15Unpad = errors.New("pkcs1v15 unpad failed")
	// ErrNotRSAPrivateKey means the private key is not RSA.
	ErrNotRSAPrivateKey = errors.New("private key is not RSA")
	// ErrEncryptedPrivateKey means the private key is encrypted; provide passphrase.
	ErrEncryptedPrivateKey = errors.New("private key is encrypted; provide passphrase")
	// ErrPKCS8NotRSA means the PKCS#8 key is not an RSA private key.
	ErrPKCS8NotRSA = errors.New("PKCS#8 key is not an RSA private key")
	// ErrEncryptedPKCS8NotSupported means encrypted PKCS#8 PEM is not supported.
	ErrEncryptedPKCS8NotSupported = errors.New("encrypted PKCS#8 PEM is not supported")
	// ErrNoRSAPrivateKeyInPEM means no RSA private key found in PEM.
	ErrNoRSAPrivateKeyInPEM = errors.New("no RSA private key found in PEM")
	// ErrDERNotRSAPrivateKey means the DER is not an RSA private key.
	ErrDERNotRSAPrivateKey = errors.New("DER is not an RSA private key")
	// ErrInvalidKeyLength means RSA key bit length is invalid for BI constraints.
	ErrInvalidKeyLength = errors.New("invalid key length")
	// ErrKeyLengthNotPowerOfTwo means key length must be a power of two.
	ErrKeyLengthNotPowerOfTwo = errors.New("key length must be a power of two")
	// ErrKeyLengthTooSmall means key length is below MinKeyBits.
	ErrKeyLengthTooSmall = errors.New("key length is below minimum")
)
