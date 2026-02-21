// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
)

// LoadPublic reads a .bikey file and returns a PublicKeyFile.
func LoadPublic(path string) (*PublicKeyFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open public key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat public key file: %w", err)
	}

	return loadPublicFromReader(f, stat.Size())
}

// LoadPublicFromReader reads .bikey bytes from r.
func LoadPublicFromReader(r io.Reader) (*PublicKeyFile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read public key data: %w", err)
	}

	return ParsePublic(data)
}

// ParsePublic parses a .bikey payload from memory.
func ParsePublic(data []byte) (*PublicKeyFile, error) {
	return loadPublicFromReader(bytes.NewReader(data), int64(len(data)))
}

// loadPublicFromReader reads public key from r. If fileSize >= 0, total size must match name+blockSize+extra.
func loadPublicFromReader(r io.Reader, fileSize int64) (*PublicKeyFile, error) {
	name, err := readName(r)
	if err != nil {
		return nil, err
	}

	blockSize, err := readU32LE(r)
	if err != nil {
		return nil, fmt.Errorf("read block size: %w", err)
	}

	if fileSize >= 0 {
		if err := checkKeyFileSize(fileSize, len(name), blockSize); err != nil {
			return nil, err
		}
	}

	headerKey, headerExtra, headerTag, err := readMetadata(r)
	if err != nil {
		return nil, err
	}

	if headerKey != PublicKeyHeader {
		return nil, fmt.Errorf("%w: want public (0x%04x) got 0x%04x", ErrInvalidKeyHeader, PublicKeyHeader, headerKey)
	}

	if headerExtra != ExtraKeyHeader {
		return nil, fmt.Errorf("%w: want extra 0x%04x got 0x%04x", ErrInvalidKeyHeader, ExtraKeyHeader, headerExtra)
	}

	if headerTag != PublicKeyTag {
		return nil, fmt.Errorf("%w: want %q got %q", ErrInvalidKeyTag, PublicKeyTag, headerTag)
	}

	lengthBits, exponent, n, err := readKeyPublicData(r)
	if err != nil {
		return nil, err
	}

	if err := validateBIBitLen(int(lengthBits), ErrInvalidPublicKey); err != nil {
		return nil, err
	}

	expectedBlock := blockSizePublic(lengthBits)
	if blockSize != expectedBlock {
		return nil, fmt.Errorf("%w: file=%d computed=%d", ErrBlockSizeMismatch, blockSize, expectedBlock)
	}

	pub := &rsa.PublicKey{N: n, E: int(exponent)}
	return &PublicKeyFile{Name: name, Key: pub}, nil
}

// WritePublic writes a .bikey file.
func WritePublic(path string, k *PublicKeyFile) error {
	data, err := MarshalPublic(k)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// WritePublicToWriter writes a .bikey payload to w.
func WritePublicToWriter(w io.Writer, k *PublicKeyFile) error {
	data, err := MarshalPublic(k)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

// MarshalPublic encodes a public key into .bikey bytes.
func MarshalPublic(k *PublicKeyFile) ([]byte, error) {
	if k == nil || k.Key == nil {
		return nil, ErrPublicKeyNil
	}

	if err := validateRSAPublicForBI(k.Key); err != nil {
		return nil, err
	}

	data, err := serializePublic(k)
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}

	return data, nil
}

// serializePublic produces the exact .bikey byte sequence (used also for embedded key in .bisign).
func serializePublic(k *PublicKeyFile) ([]byte, error) {
	pub := k.Key
	lengthBits := safeU32(pub.N.BitLen())
	blockSize := blockSizePublic(lengthBits)

	var buf bytes.Buffer

	if err := writeKeyHeader(&buf, k.Name, blockSize, PublicKeyHeader, ExtraKeyHeader, PublicKeyTag, lengthBits, safeU32(pub.E)); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, pub.N, lengthBits/8); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// FromRSAPublic builds a PublicKeyFile from an existing RSA public key.
func FromRSAPublic(name string, key *rsa.PublicKey) (*PublicKeyFile, error) {
	if err := validateRSAPublicForBI(key); err != nil {
		return nil, err
	}

	return &PublicKeyFile{Name: name, Key: key}, nil
}
