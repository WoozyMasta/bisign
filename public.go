// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/bisign

package bisign

import (
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // fingerprint only
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// PublicEqual checks RSA public key equality by exponent and modulus.
func PublicEqual(a *rsa.PublicKey, b *rsa.PublicKey) bool {
	if a == nil || b == nil || a.N == nil || b.N == nil {
		return false
	}

	if a.E != b.E {
		return false
	}

	return a.N.Cmp(b.N) == 0
}

// ModulusSHA256 returns SHA256 digest of fixed-width modulus bytes.
func ModulusSHA256(pub *rsa.PublicKey) string {
	if err := validateRSAPublicBasic(pub); err != nil {
		return ""
	}

	sum := sha256.Sum256(publicModulusBytes(pub))
	return hex.EncodeToString(sum[:])
}

// PublicFromPrivateFile loads a .biprivatekey and returns its public part.
func PublicFromPrivateFile(path string) (*PublicKeyFile, error) {
	priv, err := LoadPrivate(path)
	if err != nil {
		return nil, err
	}

	pub := priv.Public()
	if pub == nil || pub.Key == nil {
		return nil, ErrPublicFromPrivateNil
	}

	return pub, nil
}

// PublicFromSignatureFile loads a .bisign and returns the embedded public key.
func PublicFromSignatureFile(path string) (*PublicKeyFile, error) {
	sig, err := LoadSignature(path)
	if err != nil {
		return nil, err
	}

	if sig.Public == nil || sig.Public.Key == nil {
		return nil, ErrMissingEmbeddedPubKey
	}

	return sig.Public, nil
}

// LoadPublicIdentity loads public RSA identity from .bikey, .biprivatekey, or .bisign.
func LoadPublicIdentity(path string) (*PublicIdentity, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ExtBIKey:
		k, err := LoadPublic(path)
		if err != nil {
			return nil, err
		}
		if k == nil || k.Key == nil {
			return nil, ErrMissingPublicKey
		}

		if err := validateRSAPublicBasic(k.Key); err != nil {
			return nil, err
		}

		return &PublicIdentity{
			Kind: IdentityKindBIKey,
			Name: k.Name,
			Key:  k.Key,
		}, nil

	case ExtBIPrivateKey:
		k, err := LoadPrivate(path)
		if err != nil {
			return nil, err
		}
		if k == nil || k.Key == nil {
			return nil, ErrMissingPrivateKey
		}

		if err := validateRSAPublicBasic(&k.Key.PublicKey); err != nil {
			return nil, err
		}

		return &PublicIdentity{
			Kind: IdentityKindBIPrivateKey,
			Name: k.Name,
			Key:  &k.Key.PublicKey,
		}, nil

	case ExtBISign:
		s, err := LoadSignature(path)
		if err != nil {
			return nil, err
		}
		if s.Public == nil || s.Public.Key == nil {
			return nil, ErrMissingEmbeddedPubKey
		}

		if err := validateRSAPublicBasic(s.Public.Key); err != nil {
			return nil, err
		}

		return &PublicIdentity{
			Kind:    IdentityKindBISign,
			Name:    s.Public.Name,
			Version: s.Version,
			Key:     s.Public.Key,
		}, nil

	default:
		if ext == "" {
			return nil, fmt.Errorf("%w: <none>", ErrUnsupportedPublicSource)
		}

		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPublicSource, ext)
	}
}

// Inspect builds file metadata from one of supported BI formats.
func Inspect(path string) (*InspectResult, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ExtBIKey:
		info, err := inspectPublicFile(path)
		if err != nil {
			return nil, err
		}

		return &InspectResult{Key: info}, nil

	case ExtBIPrivateKey:
		info, err := inspectPrivateFile(path)
		if err != nil {
			return nil, err
		}

		return &InspectResult{Key: info}, nil

	case ExtBISign:
		info, err := inspectSignatureFile(path)
		if err != nil {
			return nil, err
		}

		return &InspectResult{Signature: info}, nil

	default:
		if ext == "" {
			return nil, fmt.Errorf("%w: <none>", ErrUnsupportedPublicSource)
		}

		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPublicSource, ext)
	}
}

// inspectPublicFile builds KeyInfo from a .bikey file.
func inspectPublicFile(path string) (*KeyInfo, error) {
	k, err := LoadPublic(path)
	if err != nil {
		return nil, err
	}
	if k == nil || k.Key == nil {
		return nil, ErrMissingPublicKey
	}
	if err := validateRSAPublicBasic(k.Key); err != nil {
		return nil, err
	}

	info := inspectPublic("bikey", path, k.Name, k.Key)
	return &info, nil
}

// inspectPrivateFile builds public-only KeyInfo from a .biprivatekey file.
func inspectPrivateFile(path string) (*KeyInfo, error) {
	k, err := LoadPrivate(path)
	if err != nil {
		return nil, err
	}
	if k == nil || k.Key == nil {
		return nil, ErrMissingPrivateKey
	}
	if err := validateRSAPublicBasic(&k.Key.PublicKey); err != nil {
		return nil, err
	}

	info := inspectPublic("biprivatekey", path, k.Name, &k.Key.PublicKey)
	return &info, nil
}

// inspectSignatureFile builds SignatureInfo from a .bisign file.
func inspectSignatureFile(path string) (*SignatureInfo, error) {
	sig, err := LoadSignature(path)
	if err != nil {
		return nil, err
	}
	if sig.Public == nil || sig.Public.Key == nil {
		return nil, ErrMissingEmbeddedPubKey
	}
	if err := validateRSAPublicBasic(sig.Public.Key); err != nil {
		return nil, err
	}

	embedded := inspectPublic("embedded-bikey", path, sig.Public.Name, sig.Public.Key)
	info := &SignatureInfo{
		Kind:        IdentityKindBISign,
		Path:        path,
		Version:     sig.Version,
		EmbeddedKey: &embedded,
	}

	hs, recoverErr := sig.RecoverHashes()
	if recoverErr != nil {
		info.RecoverError = recoverErr.Error()
	} else {
		info.Hashes = &hs
	}

	return info, nil
}

// inspectPublic converts RSA public key parameters into metadata DTO.
func inspectPublic(kind string, path string, name string, pub *rsa.PublicKey) KeyInfo {
	if name == "" {
		name = "<unknown>"
	}

	nBytes := publicModulusBytes(pub)
	sha256Sum := sha256.Sum256(nBytes)
	sha1Sum := sha1.Sum(nBytes) //nolint:gosec // fingerprint only

	rsaBits := 0
	rsaExponent := 0
	if pub != nil {
		rsaExponent = pub.E
		if pub.N != nil {
			rsaBits = pub.N.BitLen()
		}
	}

	return KeyInfo{
		Kind:          kind,
		Path:          path,
		Name:          name,
		RSABits:       rsaBits,
		RSAExponent:   rsaExponent,
		ModulusBytes:  len(nBytes),
		ModulusSHA1:   hex.EncodeToString(sha1Sum[:]),
		ModulusSHA256: hex.EncodeToString(sha256Sum[:]),
	}
}

// publicModulusBytes returns fixed-width modulus bytes aligned to key size.
func publicModulusBytes(pub *rsa.PublicKey) []byte {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E <= 1 {
		return nil
	}

	keySize := pub.Size()
	nBytes := make([]byte, keySize)
	nb := pub.N.Bytes()
	copy(nBytes[keySize-len(nb):], nb)
	return nBytes
}
