// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"os"
)

// LoadPrivate reads a .biprivatekey file and returns a PrivateKeyFile.
// The RSA key is validated and Precompute is applied.
func LoadPrivate(path string) (*PrivateKeyFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private key file: %w", err)
	}

	return loadPrivateFromReader(f, stat.Size())
}

// LoadPrivateFromReader reads .biprivatekey bytes from r.
func LoadPrivateFromReader(r io.Reader) (*PrivateKeyFile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read private key data: %w", err)
	}

	return ParsePrivate(data)
}

// ParsePrivate parses a .biprivatekey payload from memory.
func ParsePrivate(data []byte) (*PrivateKeyFile, error) {
	return loadPrivateFromReader(bytes.NewReader(data), int64(len(data)))
}

// loadPrivateFromReader reads private key from r. If fileSize >= 0, total size must match name+blockSize+extra.
func loadPrivateFromReader(r io.Reader, fileSize int64) (*PrivateKeyFile, error) {
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

	if headerKey != PrivateKeyHeader {
		return nil, fmt.Errorf("%w: want private (0x%04x) got 0x%04x", ErrInvalidKeyHeader, PrivateKeyHeader, headerKey)
	}

	if headerExtra != ExtraKeyHeader {
		return nil, fmt.Errorf("%w: want extra 0x%04x got 0x%04x", ErrInvalidKeyHeader, ExtraKeyHeader, headerExtra)
	}

	if headerTag != PrivateKeyTag {
		return nil, fmt.Errorf("%w: want %q got %q", ErrInvalidKeyTag, PrivateKeyTag, headerTag)
	}

	lengthBits, exponent, fileN, err := readKeyPublicData(r)
	if err != nil {
		return nil, err
	}

	if err := validateBIBitLen(int(lengthBits), ErrInvalidPrivateKey); err != nil {
		return nil, err
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fileN,
			E: int(exponent),
		},
	}

	p, err := readReversedBigInt(r, lengthBits/16)
	if err != nil {
		return nil, fmt.Errorf("read P: %w", err)
	}

	q, err := readReversedBigInt(r, lengthBits/16)
	if err != nil {
		return nil, fmt.Errorf("read Q: %w", err)
	}

	_, err = readReversedBigInt(r, lengthBits/16)
	if err != nil {
		return nil, fmt.Errorf("read Dp: %w", err)
	}

	_, err = readReversedBigInt(r, lengthBits/16)
	if err != nil {
		return nil, fmt.Errorf("read Dq: %w", err)
	}

	_, err = readReversedBigInt(r, lengthBits/16)
	if err != nil {
		return nil, fmt.Errorf("read Qinv: %w", err)
	}

	d, err := readReversedBigInt(r, lengthBits/8)
	if err != nil {
		return nil, fmt.Errorf("read D: %w", err)
	}

	key.Primes = []*big.Int{p, q}
	key.D = d

	calcN := new(big.Int).Mul(p, q)
	if fileN.Cmp(calcN) != 0 {
		return nil, fmt.Errorf("%w: modulus mismatch", ErrInvalidPrivateKey)
	}

	key.N = calcN
	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	expectedBlock := blockSizePrivate(lengthBits)
	if blockSize != expectedBlock {
		return nil, fmt.Errorf("%w: file=%d computed=%d", ErrBlockSizeMismatch, blockSize, expectedBlock)
	}

	return &PrivateKeyFile{Name: name, Key: key}, nil
}

// WritePrivate writes a .biprivatekey file. Key must be non-nil and valid (Precompute called).
func WritePrivate(path string, k *PrivateKeyFile) error {
	data, err := MarshalPrivate(k)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// WritePrivateToWriter writes a .biprivatekey payload to w.
func WritePrivateToWriter(w io.Writer, k *PrivateKeyFile) error {
	data, err := MarshalPrivate(k)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

// MarshalPrivate encodes a private key into .biprivatekey bytes.
func MarshalPrivate(k *PrivateKeyFile) ([]byte, error) {
	if k == nil || k.Key == nil {
		return nil, ErrPrivateKeyNil
	}

	if err := validateRSAPrivateForBIWrite(k.Key); err != nil {
		return nil, err
	}

	data, err := serializePrivate(k)
	if err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	return data, nil
}

// serializePrivate produces the exact .biprivatekey byte sequence.
func serializePrivate(k *PrivateKeyFile) ([]byte, error) {
	key := k.Key
	lengthBits := safeU32(key.N.BitLen())
	blockSize := blockSizePrivate(lengthBits)

	var buf bytes.Buffer

	if err := writeKeyHeader(&buf, k.Name, blockSize, PrivateKeyHeader, ExtraKeyHeader, PrivateKeyTag, lengthBits, safeU32(key.E)); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.N, lengthBits/8); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.Primes[0], lengthBits/16); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.Primes[1], lengthBits/16); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.Precomputed.Dp, lengthBits/16); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.Precomputed.Dq, lengthBits/16); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.Precomputed.Qinv, lengthBits/16); err != nil {
		return nil, err
	}

	if err := writeReversedBigInt(&buf, key.D, lengthBits/8); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Generate creates a new RSA key pair. bits must be a power of two.
func Generate(name string, bits int) (*PrivateKeyFile, error) {
	if err := validateKeyBitLen(bits); err != nil {
		return nil, err
	}

	bits32 := safeU32(bits)

	var (
		key *rsa.PrivateKey
		err error
	)

	// Go runtime blocks insecure key sizes in rsa.GenerateKey by default.
	// BI tooling uses 512-bit keys, so we generate those keys locally.
	if bits32 < 1024 {
		key, err = generateTwoPrimeRSA(int(bits32))
	} else {
		key, err = rsa.GenerateKey(rand.Reader, int(bits32))
	}

	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	return &PrivateKeyFile{Name: name, Key: key}, nil
}

// generateTwoPrimeRSA builds an RSA key without relying on rsa.GenerateKey runtime bit-size policy.
func generateTwoPrimeRSA(bits int) (*rsa.PrivateKey, error) {
	const (
		publicExponent = 65537
		maxAttempts    = 128
	)

	one := big.NewInt(1)
	e := big.NewInt(publicExponent)
	pBits := bits / 2
	qBits := bits - pBits

	for range maxAttempts {
		p, err := rand.Prime(rand.Reader, pBits)
		if err != nil {
			return nil, err
		}

		q, err := rand.Prime(rand.Reader, qBits)
		if err != nil {
			return nil, err
		}

		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}

		pMinusOne := new(big.Int).Sub(p, one)
		qMinusOne := new(big.Int).Sub(q, one)
		phi := new(big.Int).Mul(pMinusOne, qMinusOne)

		gcd := new(big.Int).GCD(nil, nil, e, phi)
		if gcd.Cmp(one) != 0 {
			continue
		}

		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: publicExponent,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}

		return key, nil
	}

	return nil, fmt.Errorf("failed to generate valid %d-bit RSA key in %d attempts", bits, maxAttempts)
}

// FromRSAPrivate builds a PrivateKeyFile from an existing RSA private key. Name is the BI key name.
// The key must be valid; Precompute is called so the result is ready for WritePrivate and SignHashes.
func FromRSAPrivate(name string, key *rsa.PrivateKey) (*PrivateKeyFile, error) {
	if err := validateRSAPrivateForBIImport(key); err != nil {
		return nil, err
	}

	return &PrivateKeyFile{Name: name, Key: key}, nil
}

// Public returns the public key file corresponding to k (same name and N, E).
func (k *PrivateKeyFile) Public() *PublicKeyFile {
	if k == nil || k.Key == nil {
		return nil
	}

	return &PublicKeyFile{
		Name: k.Name,
		Key:  &k.Key.PublicKey,
	}
}
