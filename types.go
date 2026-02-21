// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import "crypto/rsa"

// Constants for BI key file format and limits.
const (
	PrivateKeyHeader = 0x0207 // Private key file header
	PublicKeyHeader  = 0x0206 // Public key file header
	ExtraKeyHeader   = 0x2400 // Extra key file header
	PrivateKeyTag    = "RSA2" // Private key tag
	PublicKeyTag     = "RSA1" // Public key tag

	// ReadHeaderExtraSize is the extra header size: 1 byte null terminator + 4 bytes block size.
	ReadHeaderExtraSize = 5
	// StaticHeaderBlockSize is the fixed header after name+null and block size:
	// 5 uint32 (HeaderKey, HeaderExtra, Tag, Length, E).
	StaticHeaderBlockSize = 20

	// MinKeyBits is the minimal supported RSA key size.
	MinKeyBits = 512
)

// Version is signature format versions supported by BI signing.
type Version uint32

// Supported BI signature versions.
const (
	// Version2 is the legacy version of BI signature format.
	Version2 Version = 2
	// Version3 is the current version of BI signature format.
	Version3 Version = 3
)

// Extension constants for BI files.
const (
	// ExtBIKey is the filename extension of BI public key files.
	ExtBIKey = ".bikey"
	// ExtBIPrivateKey is the filename extension of BI private key files.
	ExtBIPrivateKey = ".biprivatekey"
	// ExtBISign is the filename extension of BI signature files.
	ExtBISign = ".bisign"
)

// IdentityKind describes which BI file format provided public identity.
type IdentityKind string

// Supported identity source kinds.
const (
	// BI key file
	IdentityKindBIKey IdentityKind = "bikey"
	// BI private key file
	IdentityKindBIPrivateKey IdentityKind = "biprivatekey"
	// BI signature file
	IdentityKindBISign IdentityKind = "bisign"
)

// PrivateKeyFile represents a loaded or to-be-saved .biprivatekey file.
type PrivateKeyFile struct {
	// RSA private key; Precompute and Validate applied after load
	Key *rsa.PrivateKey `json:"key,omitempty" yaml:"key,omitempty"`

	// Key name
	Name string `json:"name" yaml:"name"`
}

// PublicKeyFile represents a loaded or to-be-saved .bikey file.
type PublicKeyFile struct {
	// RSA public key
	Key *rsa.PublicKey `json:"key,omitempty" yaml:"key,omitempty"`

	// Key name
	Name string `json:"name" yaml:"name"`
}

// SignatureFile represents a .bisign file: embedded public key and three signature blocks.
type SignatureFile struct {
	// Used by RecoverHashes and VerifyHashes
	Public *PublicKeyFile `json:"public,omitempty" yaml:"public,omitempty"`

	// First Raw signature block, LE
	Block1 []byte `json:"block1,omitempty" yaml:"block1,omitempty"`

	// Second Raw signature block, LE
	Block2 []byte `json:"block2,omitempty" yaml:"block2,omitempty"`

	// Third Raw signature block, LE
	Block3 []byte `json:"block3,omitempty" yaml:"block3,omitempty"`

	// Signature format version (2 or 3)
	Version Version `json:"version" yaml:"version"`
}

// HashSet holds the three SHA1 digests used by BI signing (hash1, hash2, hash3).
type HashSet struct {
	Hash1 [20]byte `json:"hash1" yaml:"hash1"` // SHA1 digest for first hash block
	Hash2 [20]byte `json:"hash2" yaml:"hash2"` // SHA1 digest for second hash block
	Hash3 [20]byte `json:"hash3" yaml:"hash3"` // SHA1 digest for third hash block
}

// PublicIdentity describes a public RSA identity loaded from BI key/signature files.
type PublicIdentity struct {
	// Actual RSA public key
	Key *rsa.PublicKey `json:"-" yaml:"-"`

	// "bikey", "biprivatekey", or "bisign"
	Kind IdentityKind `json:"kind" yaml:"kind"`

	// Embedded BI key name
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Signature version for Kind="bisign"
	Version Version `json:"version,omitempty" yaml:"version,omitempty"`
}

// KeyInfo describes public RSA metadata for BI key material.
type KeyInfo struct {
	// Source kind ("bikey", "biprivatekey", "embedded-bikey")
	Kind string `json:"kind" yaml:"kind"`

	// Source file path used for inspection
	Path string `json:"path,omitempty" yaml:"path,omitempty"`

	// BI key name stored in source
	Name string `json:"name" yaml:"name"`

	// SHA1 digest of fixed-width modulus bytes
	ModulusSHA1 string `json:"modulus_sha1" yaml:"modulus_sha1"`

	// SHA256 digest of fixed-width modulus bytes
	ModulusSHA256 string `json:"modulus_sha256" yaml:"modulus_sha256"`

	// RSA modulus size in bits
	RSABits int `json:"rsa_bits" yaml:"rsa_bits"`

	// RSA public exponent
	RSAExponent int `json:"rsa_exponent" yaml:"rsa_exponent"`

	// Fixed-width modulus length in bytes
	ModulusBytes int `json:"modulus_bytes" yaml:"modulus_bytes"`
}

// SignatureInfo describes .bisign metadata with embedded key and recovered hashes.
type SignatureInfo struct {
	// Metadata of key embedded in .bisign
	EmbeddedKey *KeyInfo `json:"embedded_key,omitempty" yaml:"embedded_key,omitempty"`

	// Recovered hashes when recovery succeeds
	Hashes *HashSet `json:"hashes,omitempty" yaml:"hashes,omitempty"`

	// Always "bisign" for signature files
	Kind IdentityKind `json:"kind" yaml:"kind"`

	// Source .bisign file path
	Path string `json:"path,omitempty" yaml:"path,omitempty"`

	// Recovery error text when hashes are unavailable
	RecoverError string `json:"recover_error,omitempty" yaml:"recover_error,omitempty"`

	// Signature format version (2 or 3)
	Version Version `json:"version" yaml:"version"`
}

// InspectResult contains metadata extracted from one supported BI file.
type InspectResult struct {
	// Key metadata for .bikey/.biprivatekey input
	Key *KeyInfo `json:"key,omitempty" yaml:"key,omitempty"`

	// Signature metadata for .bisign input
	Signature *SignatureInfo `json:"signature,omitempty" yaml:"signature,omitempty"`
}
