// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// sha1ASNPrefix is the DigestInfo prefix for PKCS#1 v1.5 SHA-1 (ASN.1).
var sha1ASNPrefix = []byte{
	0x30, 0x21, 0x30, 0x09,
	0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05,
	0x00, 0x04, 0x14,
}

const stackKeyBufferBytes = 4096 / 8

// signHash signs a 20-byte SHA1 digest with PKCS#1 v1.5 and returns the signature (key size bytes).
func signHash(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	if len(digest) != 20 {
		return nil, fmt.Errorf("digest must be 20 bytes, got %d", len(digest))
	}

	if key.Size()*8 < 1024 {
		return signHashInsecureKeySize(key, digest)
	}

	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
}

// signHashInsecureKeySize signs SHA1 digest for BI-compatible small RSA keys.
func signHashInsecureKeySize(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	keySize := key.Size()
	em, err := emsaPKCS1v15SHA1(keySize, digest)
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(em)
	if key.N == nil || m.Cmp(key.N) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	s := new(big.Int).Exp(m, key.D, key.N)
	sig := make([]byte, keySize)
	s.FillBytes(sig)
	return sig, nil
}

// emsaPKCS1v15SHA1 builds PKCS#1 v1.5 encoded message for SHA1 digest.
func emsaPKCS1v15SHA1(keySize int, digest []byte) ([]byte, error) {
	tLen := len(sha1ASNPrefix) + len(digest)
	psLen := keySize - tLen - 3
	if psLen < 8 {
		return nil, fmt.Errorf("%w: key too small for PKCS#1 v1.5 SHA1", ErrInvalidPrivateKey)
	}

	em := make([]byte, keySize)
	em[0] = 0x00
	em[1] = 0x01
	for i := 2; i < 2+psLen; i++ {
		em[i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[3+psLen:], sha1ASNPrefix)
	copy(em[3+psLen+len(sha1ASNPrefix):], digest)
	return em, nil
}

// verifyHashBlock verifies one BI signature block against one SHA1 digest.
func verifyHashBlock(pub *rsa.PublicKey, block []byte, digest []byte) error {
	if err := validateRSAPublicForOp(pub); err != nil {
		return err
	}

	keySize := pub.Size()
	if len(block) != keySize {
		return fmt.Errorf("%w: got=%d expected=%d", ErrSignatureSize, len(block), keySize)
	}
	if len(digest) != 20 {
		return fmt.Errorf("digest must be 20 bytes, got %d", len(digest))
	}

	if keySize*8 >= 1024 {
		var sigBEFixed [stackKeyBufferBytes]byte
		sigBE := allocKeyTempBuffer(keySize, &sigBEFixed)
		copy(sigBE, block)
		reverseBytes(sigBE)

		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, sigBE); err != nil {
			return ErrVerifyFailed
		}

		return nil
	}

	recovered, err := recoverDigestFromBlock(pub, block)
	if err != nil {
		return ErrVerifyFailed
	}

	if !bytes.Equal(recovered[:], digest) {
		return ErrVerifyFailed
	}

	return nil
}

// recoverDigestFromBlock reverses the LE signature block, applies RSA public operation, then unpads PKCS#1 v1.5 SHA1.
func recoverDigestFromBlock(pub *rsa.PublicKey, block []byte) ([20]byte, error) {
	var out [20]byte

	if err := validateRSAPublicForOp(pub); err != nil {
		return out, err
	}

	keySize := pub.Size()
	if len(block) != keySize {
		return out, fmt.Errorf("%w: got=%d expected=%d", ErrSignatureSize, len(block), keySize)
	}

	var sigBEFixed [stackKeyBufferBytes]byte
	sigBE := allocKeyTempBuffer(keySize, &sigBEFixed)
	copy(sigBE, block)
	reverseBytes(sigBE)

	s := new(big.Int).SetBytes(sigBE)
	if s.Sign() <= 0 {
		return out, ErrInvalidSignatureInt
	}

	var e big.Int
	e.SetInt64(int64(pub.E))

	m := new(big.Int).Exp(s, &e, pub.N)

	var emFixed [stackKeyBufferBytes]byte
	em := allocKeyTempBuffer(keySize, &emFixed)
	m.FillBytes(em)

	digest, ok := unpadPKCS1v15SHA1(em)
	if !ok {
		return out, ErrPKCS1v15Unpad
	}

	copy(out[:], digest)
	return out, nil
}

// allocKeyTempBuffer returns stack-backed buffer for common key sizes and heap buffer for larger keys.
func allocKeyTempBuffer(keySize int, stack *[stackKeyBufferBytes]byte) []byte {
	if keySize <= len(stack) {
		return stack[:keySize]
	}

	return make([]byte, keySize)
}

// unpadPKCS1v15SHA1 extracts the 20-byte SHA1 digest from PKCS#1 v1.5 padded message.
func unpadPKCS1v15SHA1(em []byte) ([]byte, bool) {
	minLen := 2 + 1 + 1 + len(sha1ASNPrefix) + 20
	if len(em) < minLen {
		return nil, false
	}

	if em[0] != 0x00 || em[1] != 0x01 {
		return nil, false
	}

	i := 2
	for i < len(em) && em[i] == 0xff {
		i++
	}

	if i >= len(em) || em[i] != 0x00 {
		return nil, false
	}
	i++

	if i+len(sha1ASNPrefix)+20 > len(em) {
		return nil, false
	}

	if !bytes.Equal(em[i:i+len(sha1ASNPrefix)], sha1ASNPrefix) {
		return nil, false
	}

	i += len(sha1ASNPrefix)
	return em[i : i+20], true
}
