// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"encoding/binary"
	"io"
	"math"
	"math/big"
)

// safeU32 converts int to uint32 for use in BI format fields; clamps to [0, math.MaxUint32].
func safeU32(i int) uint32 {
	if i <= 0 {
		return 0
	}

	if i > math.MaxUint32 {
		return math.MaxUint32
	}

	return uint32(i)
}

// readU32LE reads a little-endian uint32 from r.
func readU32LE(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b[:]), nil
}

// writeU32LE writes v as little-endian uint32 to w.
func writeU32LE(w io.Writer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// readReversedBigInt reads exactly size bytes in little-endian (reversed) order and returns a big.Int.
func readReversedBigInt(r io.Reader, size uint32) (*big.Int, error) {
	buf := make([]byte, size)

	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	reverseBytes(buf)
	return new(big.Int).SetBytes(buf), nil
}

// writeReversedBigInt writes the big.Int as exactly size bytes in little-endian (reversed) order.
// The value is right-padded with zero bytes if it has fewer than size bytes.
func writeReversedBigInt(w io.Writer, n *big.Int, size uint32) error {
	raw := n.Bytes()
	rawLen := safeU32(len(raw))

	if rawLen > size {
		raw = raw[len(raw)-int(size):]
		rawLen = size
	}

	buf := make([]byte, size)
	copy(buf[size-rawLen:], raw)
	reverseBytes(buf)
	_, err := w.Write(buf)
	return err
}

// reverseBytes reverses b in place.
func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// isPowerOfTwo returns true if n is a power of two (and n > 0).
func isPowerOfTwo(n uint32) bool {
	return n > 0 && (n&(n-1)) == 0
}
