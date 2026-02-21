// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LoadRSAPrivate loads RSA private key from OpenSSH, PEM, or DER formats.
// When key is encrypted, passphrase must be provided.
func LoadRSAPrivate(path string, passphrase string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// ssh-keygen default output is "OPENSSH PRIVATE KEY" PEM. Let ssh handle it first.
	{
		var (
			v   any
			err error
		)
		if passphrase != "" {
			v, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
		} else {
			v, err = ssh.ParseRawPrivateKey(data)
		}

		if err == nil {
			key, ok := v.(*rsa.PrivateKey)
			if !ok {
				return nil, ErrNotRSAPrivateKey
			}
			return key, nil
		}

		if isIncorrectPassword(err) {
			return nil, fmt.Errorf("incorrect passphrase for %s", path)
		}

		if isPassphraseMissing(err) {
			return nil, ErrEncryptedPrivateKey
		}
	}

	if hasPEM(data) {
		return parseRSAPrivatePEM(path, data, passphrase)
	}

	return parseRSAPrivateDER(data)
}

// hasPEM checks whether input looks like PEM.
func hasPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}

// parseRSAPrivatePEM parses RSA private key from PEM, including legacy encrypted PEM blocks.
func parseRSAPrivatePEM(path string, data []byte, passphrase string) (*rsa.PrivateKey, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if isLegacyEncryptedPEMBlock(block) {
			if passphrase == "" {
				return nil, ErrEncryptedPrivateKey
			}

			decrypted, err := x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck // still best available for legacy encrypted PEM
			if err != nil {
				if isIncorrectPassword(err) {
					return nil, fmt.Errorf("incorrect passphrase for %s", path)
				}
				return nil, fmt.Errorf("decrypt PEM: %w", err)
			}
			block.Bytes = decrypted
		}

		switch strings.TrimSpace(block.Type) {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#1 PEM: %w", err)
			}
			return key, nil

		case "PRIVATE KEY":
			v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#8 PEM: %w", err)
			}
			key, ok := v.(*rsa.PrivateKey)
			if !ok {
				return nil, ErrPKCS8NotRSA
			}
			return key, nil

		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("%w; provide unencrypted PEM or OpenSSH key", ErrEncryptedPKCS8NotSupported)
		}
	}

	return nil, ErrNoRSAPrivateKeyInPEM
}

// isLegacyEncryptedPEMBlock checks legacy PEM encryption headers.
func isLegacyEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}

	if _, ok := block.Headers["DEK-Info"]; ok {
		return true
	}

	v, ok := block.Headers["Proc-Type"]
	return ok && strings.Contains(strings.ToUpper(v), "ENCRYPTED")
}

// parseRSAPrivateDER parses RSA private key from DER (PKCS#1 or PKCS#8).
func parseRSAPrivateDER(data []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	v, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse DER (PKCS#1/PKCS#8): %w", err)
	}
	key, ok := v.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrDERNotRSAPrivateKey
	}

	return key, nil
}

// isIncorrectPassword normalizes incorrect passphrase detection across parsers.
func isIncorrectPassword(err error) bool {
	return errors.Is(err, x509.IncorrectPasswordError)
}

// isPassphraseMissing reports whether OpenSSH parser requires passphrase input.
func isPassphraseMissing(err error) bool {
	var pm *ssh.PassphraseMissingError
	ok := errors.As(err, &pm)
	return ok
}
