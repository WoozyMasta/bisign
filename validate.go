// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"crypto/rsa"
	"fmt"
)

// validateVersion checks whether v is one of the supported signature versions.
func validateVersion(v Version) error {
	if v != Version2 && v != Version3 {
		return fmt.Errorf("%w: %d (allowed 2, 3)", ErrUnsupportedVersion, v)
	}

	return nil
}

// validateRSAPublicBasic verifies minimum public-key invariants used by helpers.
func validateRSAPublicBasic(pub *rsa.PublicKey) error {
	if pub == nil {
		return ErrPublicKeyNil
	}

	if pub.N == nil || pub.N.Sign() <= 0 || pub.E <= 1 {
		return ErrInvalidPublicKey
	}

	return nil
}

// validateRSAPublicForOp verifies public key invariants for raw RSA operations.
func validateRSAPublicForOp(pub *rsa.PublicKey) error {
	if pub == nil {
		return ErrPublicOpNilPublicKey
	}

	if pub.N == nil || pub.N.Sign() <= 0 || pub.E <= 1 {
		return ErrInvalidPublicKey
	}

	if err := validateBIBitLen(pub.N.BitLen(), ErrInvalidPublicKey); err != nil {
		return err
	}

	return nil
}

// validateRSAPublicForBI verifies that public key can be encoded in BI key format.
func validateRSAPublicForBI(pub *rsa.PublicKey) error {
	if err := validateRSAPublicBasic(pub); err != nil {
		return err
	}

	if err := validateBIBitLen(pub.N.BitLen(), ErrInvalidPublicKey); err != nil {
		return err
	}

	return nil
}

// validateRSAPrivateForSign verifies minimum private-key invariants for signing.
func validateRSAPrivateForSign(key *rsa.PrivateKey) error {
	if key == nil {
		return ErrPrivateKeyNil
	}

	if key.N == nil || key.N.Sign() <= 0 || key.D == nil || key.D.Sign() <= 0 || key.E <= 1 {
		return ErrInvalidPrivateKey
	}

	return nil
}

// validateRSAPrivateForBIWrite verifies that private key can be encoded in BI key format.
//
// This path is used by WritePrivate and stays lightweight: it validates structural
// invariants and ensures CRT params are present without running full RSA validation.
func validateRSAPrivateForBIWrite(key *rsa.PrivateKey) error {
	if err := validateRSAPrivateForSign(key); err != nil {
		return err
	}

	if len(key.Primes) < 2 || key.Primes[0] == nil || key.Primes[1] == nil {
		return ErrInvalidPrivateKey
	}

	if err := validateBIBitLen(key.N.BitLen(), ErrInvalidPrivateKey); err != nil {
		return err
	}

	if !hasRSAStaticPrecomputed(key) {
		key.Precompute()
	}

	if !hasRSAStaticPrecomputed(key) {
		return ErrInvalidPrivateKey
	}

	return nil
}

// validateRSAPrivateForBIImport verifies private key for import path.
//
// This path performs full RSA validation because it is not performance critical.
func validateRSAPrivateForBIImport(key *rsa.PrivateKey) error {
	if err := validateRSAPrivateForBIWrite(key); err != nil {
		return err
	}

	if err := key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	return nil
}

// hasRSAStaticPrecomputed reports whether CRT params are ready for BI private key encoding.
func hasRSAStaticPrecomputed(key *rsa.PrivateKey) bool {
	if key == nil {
		return false
	}

	return key.Precomputed.Dp != nil &&
		key.Precomputed.Dq != nil &&
		key.Precomputed.Qinv != nil
}

// validateBIBitLen checks BI key bit-length constraints for supplied baseErr.
func validateBIBitLen(bits int, baseErr error) error {
	if err := validateKeyBitLen(bits); err != nil {
		return fmt.Errorf("%w: %w", baseErr, err)
	}

	return nil
}

// validateKeyBitLen checks BI key bit-length constraints.
func validateKeyBitLen(bits int) error {
	bits32 := safeU32(bits)
	if !isPowerOfTwo(bits32) {
		return fmt.Errorf(
			"%w: %w: got=%d",
			ErrInvalidKeyLength,
			ErrKeyLengthNotPowerOfTwo,
			bits,
		)
	}

	if bits32 < MinKeyBits {
		return fmt.Errorf(
			"%w: %w: got=%d min=%d",
			ErrInvalidKeyLength,
			ErrKeyLengthTooSmall,
			bits,
			MinKeyBits,
		)
	}

	return nil
}

// validateSignatureFile checks public key, version, and block sizes.
func validateSignatureFile(s *SignatureFile) error {
	if s == nil {
		return ErrSignatureNil
	}

	if s.Public == nil || s.Public.Key == nil {
		return ErrMissingEmbeddedPubKey
	}

	if err := validateRSAPublicForOp(s.Public.Key); err != nil {
		return err
	}

	if err := validateVersion(s.Version); err != nil {
		return err
	}

	keySize := s.Public.Key.Size()
	if len(s.Block1) != keySize {
		return fmt.Errorf("%w: block1 got=%d expected=%d", ErrSignatureSize, len(s.Block1), keySize)
	}

	if len(s.Block2) != keySize {
		return fmt.Errorf("%w: block2 got=%d expected=%d", ErrSignatureSize, len(s.Block2), keySize)
	}

	if len(s.Block3) != keySize {
		return fmt.Errorf("%w: block3 got=%d expected=%d", ErrSignatureSize, len(s.Block3), keySize)
	}

	return nil
}
