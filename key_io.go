// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"fmt"
	"io"
	"math/big"
)

// blockSizePrivate returns the key block size for a .biprivatekey (after name+null and block size field).
func blockSizePrivate(lengthBits uint32) uint32 {
	// StaticHeaderBlockSize (5 uint32) + N(length/8) + P,Q,Dp,Dq,Qinv(length/16 each) + D(length/8)
	return StaticHeaderBlockSize + (lengthBits/8)*2 + (lengthBits/16)*5
}

// blockSizePublic returns the key block size for a .bikey (fixed-width modulus).
func blockSizePublic(lengthBits uint32) uint32 {
	return StaticHeaderBlockSize + lengthBits/8
}

// readName reads a null-terminated key name from r.
func readName(r io.Reader) (string, error) {
	var name []byte

	for {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read name: %w", err)
		}

		if b[0] == 0 {
			break
		}
		name = append(name, b[0])
	}

	return string(name), nil
}

// readMetadata reads HeaderKey, HeaderExtra, and 4-byte HeaderTag (e.g. "RSA1").
func readMetadata(r io.Reader) (headerKey, headerExtra uint32, headerTag string, err error) {
	headerKey, err = readU32LE(r)
	if err != nil {
		return 0, 0, "", fmt.Errorf("read HeaderKey: %w", err)
	}

	headerExtra, err = readU32LE(r)
	if err != nil {
		return 0, 0, "", fmt.Errorf("read HeaderExtra: %w", err)
	}

	var tag [4]byte
	if _, err = io.ReadFull(r, tag[:]); err != nil {
		return 0, 0, "", fmt.Errorf("read HeaderTag: %w", err)
	}

	return headerKey, headerExtra, string(tag[:]), nil
}

// readKeyPublicData reads length (bits), exponent E, and modulus N (reversed LE).
func readKeyPublicData(r io.Reader) (lengthBits uint32, exponent uint32, n *big.Int, err error) {
	lengthBits, err = readU32LE(r)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("read key length: %w", err)
	}

	exponent, err = readU32LE(r)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("read exponent: %w", err)
	}

	n, err = readReversedBigInt(r, lengthBits/8)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("read modulus: %w", err)
	}

	return lengthBits, exponent, n, nil
}

// checkKeyFileSize verifies file size equals nameLen + 4 + blockSize.
func checkKeyFileSize(fileSize int64, nameLen int, blockSize uint32) error {
	want := int64(nameLen) + int64(ReadHeaderExtraSize) + int64(blockSize)
	if fileSize != want {
		return fmt.Errorf("%w: expected=%d got=%d", ErrBlockSizeMismatch, want, fileSize)
	}
	return nil
}

// writeKeyHeader writes name\0, blockSize (LE), headerKey, headerExtra, tag (4 bytes), length (LE), exponent (LE).
func writeKeyHeader(w io.Writer, name string, blockSize, headerKey, headerExtra uint32, tag string, lengthBits, exponent uint32) error {
	if _, err := w.Write(append([]byte(name), 0)); err != nil {
		return err
	}

	if err := writeU32LE(w, blockSize); err != nil {
		return err
	}

	if err := writeU32LE(w, headerKey); err != nil {
		return err
	}

	if err := writeU32LE(w, headerExtra); err != nil {
		return err
	}

	tagBytes := []byte(tag)
	if len(tagBytes) != 4 {
		return fmt.Errorf("key tag must be 4 bytes, got %q", tag)
	}

	if _, err := w.Write(tagBytes); err != nil {
		return err
	}

	if err := writeU32LE(w, lengthBits); err != nil {
		return err
	}

	return writeU32LE(w, exponent)
}
