// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// LoadSignature reads a .bisign file (embedded public key + three signature blocks).
func LoadSignature(path string) (*SignatureFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open signature file: %w", err)
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat signature file: %w", err)
	}

	if err := checkInputSize(stat.Size(), MaxSignatureFileBytes); err != nil {
		return nil, err
	}

	return loadSignatureFromReader(f)
}

// LoadSignatureFromReader reads .bisign bytes from r.
func LoadSignatureFromReader(r io.Reader) (*SignatureFile, error) {
	return loadSignatureFromReader(r)
}

// ParseSignature parses a .bisign payload from memory.
func ParseSignature(data []byte) (*SignatureFile, error) {
	if err := checkInputSize(int64(len(data)), MaxSignatureFileBytes); err != nil {
		return nil, err
	}

	return loadSignatureFromReader(bytes.NewReader(data))
}

// loadSignatureFromReader reads a .bisign payload.
func loadSignatureFromReader(r io.Reader) (*SignatureFile, error) {
	pub, err := loadPublicFromReader(r, -1)
	if err != nil {
		return nil, fmt.Errorf("read embedded public key: %w", err)
	}

	block1, err := readSigBlock(r, pub.Key.Size())
	if err != nil {
		return nil, fmt.Errorf("read block1: %w", err)
	}

	versionRaw, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}

	version := Version(versionRaw)
	if err := validateSignatureVersion(version); err != nil {
		return nil, err
	}

	block2, err := readSigBlock(r, pub.Key.Size())
	if err != nil {
		return nil, fmt.Errorf("read block2: %w", err)
	}

	block3, err := readSigBlock(r, pub.Key.Size())
	if err != nil {
		return nil, fmt.Errorf("read block3: %w", err)
	}

	sig := &SignatureFile{
		Public:  pub,
		Version: version,
		Block1:  block1,
		Block2:  block2,
		Block3:  block3,
	}
	if err := ensureReaderEOF(r); err != nil {
		return nil, err
	}

	if err := validateSignatureFile(sig); err != nil {
		return nil, err
	}

	return sig, nil
}

// ensureReaderEOF rejects trailing bytes after a complete payload.
func ensureReaderEOF(r io.Reader) error {
	var extra [1]byte
	n, err := io.ReadFull(r, extra[:])
	if n != 0 {
		return ErrTrailingData
	}

	if err == io.EOF {
		return nil
	}

	if err != nil {
		return fmt.Errorf("check trailing data: %w", err)
	}

	return nil
}

// readSigBlock reads a block only when its size matches the RSA key size.
func readSigBlock(r io.Reader, expectedSize int) ([]byte, error) {
	size, err := readU32LE(r)
	if err != nil {
		return nil, err
	}

	if int64(size) != int64(expectedSize) {
		return nil, fmt.Errorf("%w: got=%d expected=%d", ErrSignatureSize, size, expectedSize)
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// WriteSignature writes a .bisign file. Block1/2/3 must already be in BI LE form (key-size bytes each).
func WriteSignature(path string, s *SignatureFile) error {
	data, err := MarshalSignature(s)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// WriteSignatureToWriter writes a .bisign payload to w.
func WriteSignatureToWriter(w io.Writer, s *SignatureFile) error {
	data, err := MarshalSignature(s)
	if err != nil {
		return err
	}

	return writePayload(w, data)
}

// MarshalSignature encodes signature data into .bisign bytes.
func MarshalSignature(s *SignatureFile) ([]byte, error) {
	if err := validateSignatureFile(s); err != nil {
		return nil, err
	}

	data, err := serializeSignature(s)
	if err != nil {
		return nil, fmt.Errorf("serialize signature: %w", err)
	}

	return data, nil
}

// serializeSignature produces the exact .bisign byte sequence.
func serializeSignature(s *SignatureFile) ([]byte, error) {
	pubData, err := serializePublic(s.Public)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(pubData)

	if err := writeSigBlockTo(&buf, s.Block1); err != nil {
		return nil, err
	}

	if err := writeU32LE(&buf, safeU32(int(s.Version))); err != nil {
		return nil, err
	}

	if err := writeSigBlockTo(&buf, s.Block2); err != nil {
		return nil, err
	}

	if err := writeSigBlockTo(&buf, s.Block3); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// writeSigBlockTo writes uint32(len(b)) (LE) then b to w.
func writeSigBlockTo(w io.Writer, b []byte) error {
	if err := writeU32LE(w, safeU32(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// SignHashes creates a SignatureFile from a private key and hash set. Version must be 2 or 3.
func (k *PrivateKeyFile) SignHashes(version Version, hs HashSet) (*SignatureFile, error) {
	if k == nil || k.Key == nil {
		return nil, ErrPrivateKeyNil
	}

	if err := validateRSAPrivateForSign(k.Key); err != nil {
		return nil, err
	}

	if err := validateSigningVersion(version); err != nil {
		return nil, err
	}

	sig1, err := signHash(k.Key, hs.Hash1[:])
	if err != nil {
		return nil, fmt.Errorf("sign hash1: %w", err)
	}

	sig2, err := signHash(k.Key, hs.Hash2[:])
	if err != nil {
		return nil, fmt.Errorf("sign hash2: %w", err)
	}

	sig3, err := signHash(k.Key, hs.Hash3[:])
	if err != nil {
		return nil, fmt.Errorf("sign hash3: %w", err)
	}

	keySize := k.Key.Size()
	block1 := make([]byte, keySize)
	copy(block1[keySize-len(sig1):], sig1)
	reverseBytes(block1)
	block2 := make([]byte, keySize)
	copy(block2[keySize-len(sig2):], sig2)
	reverseBytes(block2)
	block3 := make([]byte, keySize)
	copy(block3[keySize-len(sig3):], sig3)
	reverseBytes(block3)

	return &SignatureFile{
		Public:  k.Public(),
		Version: version,
		Block1:  block1,
		Block2:  block2,
		Block3:  block3,
	}, nil
}

// RecoverHashes recovers the three SHA1 digests from the signature blocks (RSA public op + PKCS#1 v1.5 unpad).
func (s *SignatureFile) RecoverHashes() (HashSet, error) {
	var hs HashSet

	if s == nil || s.Public == nil || s.Public.Key == nil {
		return hs, ErrMissingEmbeddedPubKey
	}

	if err := validateRSAPublicForOp(s.Public.Key); err != nil {
		return hs, err
	}

	h1, err := recoverDigestFromBlock(s.Public.Key, s.Block1)
	if err != nil {
		return hs, fmt.Errorf("recover hash1: %w", err)
	}

	h2, err := recoverDigestFromBlock(s.Public.Key, s.Block2)
	if err != nil {
		return hs, fmt.Errorf("recover hash2: %w", err)
	}

	h3, err := recoverDigestFromBlock(s.Public.Key, s.Block3)
	if err != nil {
		return hs, fmt.Errorf("recover hash3: %w", err)
	}

	hs.Hash1 = h1
	hs.Hash2 = h2
	hs.Hash3 = h3
	return hs, nil
}

// VerifyHashes verifies the hash and signature block selected by the signature version.
func (s *SignatureFile) VerifyHashes(hs HashSet) error {
	if s == nil || s.Public == nil || s.Public.Key == nil {
		return ErrMissingEmbeddedPubKey
	}

	if err := validateRSAPublicForOp(s.Public.Key); err != nil {
		return err
	}

	if err := validateSignatureVersion(s.Version); err != nil {
		return err
	}

	switch s.Version {
	case Version1:
		return verifyHashBlock(s.Public.Key, s.Block1, hs.Hash1[:])

	case Version2:
		return verifyHashBlock(s.Public.Key, s.Block2, hs.Hash2[:])

	case Version3:
		return verifyHashBlock(s.Public.Key, s.Block3, hs.Hash3[:])
	}

	return ErrUnsupportedVersion
}
