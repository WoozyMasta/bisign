package bisign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGenerateLoadWriteRoundtrip(t *testing.T) {
	dir := t.TempDir()

	priv, err := Generate("testkey", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privPath := filepath.Join(dir, "test.biprivatekey")
	pubPath := filepath.Join(dir, "test.bikey")

	if err := WritePrivate(privPath, priv); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}

	if err := WritePublic(pubPath, priv.Public()); err != nil {
		t.Fatalf("WritePublic: %v", err)
	}

	loadedPriv, err := LoadPrivate(privPath)
	if err != nil {
		t.Fatalf("LoadPrivate: %v", err)
	}

	if loadedPriv.Name != priv.Name {
		t.Errorf("name: got %q want %q", loadedPriv.Name, priv.Name)
	}

	if loadedPriv.Key.N.Cmp(priv.Key.N) != 0 {
		t.Error("modulus mismatch after roundtrip")
	}

	loadedPub, err := LoadPublic(pubPath)
	if err != nil {
		t.Fatalf("LoadPublic: %v", err)
	}

	if loadedPub.Name != priv.Public().Name {
		t.Errorf("pub name: got %q want %q", loadedPub.Name, priv.Public().Name)
	}

	if loadedPub.Key.N.Cmp(priv.Key.PublicKey.N) != 0 {
		t.Error("public modulus mismatch after roundtrip")
	}
}

func TestLoadRSAPrivateRejectsOpenSSH(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "id_rsa")
	data := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadRSAPrivate(path, "")
	if !errors.Is(err, ErrOpenSSHPrivateKeyUnsupported) {
		t.Fatalf("expected ErrOpenSSHPrivateKeyUnsupported, got: %v", err)
	}
}

// TestLoadRSAPrivateSupportedEncodings covers each supported private-key container.
func TestLoadRSAPrivateSupportedEncodings(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{name: "PKCS1 DER", data: pkcs1DER},
		{name: "PKCS8 DER", data: pkcs8DER},
		{
			name: "PKCS1 PEM",
			data: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1DER}),
		},
		{
			name: "PKCS8 PEM",
			data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, testCase.data, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			loaded, err := LoadRSAPrivate(path, "")
			if err != nil {
				t.Fatalf("LoadRSAPrivate: %v", err)
			}

			assertRSAPrivateKeyEqual(t, key, loaded)
		})
	}
}

// TestLoadRSAPrivateInvalidInputs covers encrypted and non-RSA import paths.
func TestLoadRSAPrivateInvalidInputs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		pkcs1DER,
		[]byte("test-passphrase"),
		x509.PEMCipherAES256,
	)
	if err != nil {
		t.Fatalf("EncryptPEMBlock: %v", err)
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey ECDSA: %v", err)
	}

	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaDER})
	nonKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("test")})
	encryptedPKCS8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("encrypted"),
	})

	testCases := []struct {
		name       string
		data       []byte
		passphrase string
		wantErr    error
	}{
		{name: "encrypted without passphrase", data: encryptedPEM, wantErr: ErrEncryptedPrivateKey},
		{name: "non-RSA PKCS8", data: ecdsaPEM, wantErr: ErrPKCS8NotRSA},
		{name: "non-RSA PKCS8 DER", data: ecdsaDER, wantErr: ErrDERNotRSAPrivateKey},
		{name: "unsupported PEM block", data: nonKeyPEM, wantErr: ErrNoRSAPrivateKeyInPEM},
		{name: "encrypted PKCS8", data: encryptedPKCS8PEM, wantErr: ErrEncryptedPKCS8NotSupported},
		{name: "truncated DER", data: []byte{0x30, 0x80, 0x00}},
		{name: "input exceeds configured limit", data: make([]byte, MaxRSAPrivateFileBytes+1), wantErr: ErrInputTooLarge},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, testCase.data, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := LoadRSAPrivate(path, testCase.passphrase)
			if testCase.wantErr == nil {
				if err == nil {
					t.Fatal("LoadRSAPrivate accepted invalid input")
				}

				return
			}

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("LoadRSAPrivate error=%v, want errors.Is(_, %v)", err, testCase.wantErr)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(path, encryptedPEM, 0600); err != nil {
		t.Fatalf("WriteFile encrypted PEM: %v", err)
	}

	loaded, err := LoadRSAPrivate(path, "test-passphrase")
	if err != nil {
		t.Fatalf("LoadRSAPrivate with passphrase: %v", err)
	}

	assertRSAPrivateKeyEqual(t, key, loaded)
	if _, err := LoadRSAPrivate(path, "wrong-passphrase"); err == nil {
		t.Fatal("LoadRSAPrivate accepted an incorrect passphrase")
	}
}

// assertRSAPrivateKeyEqual compares key material preserved by private-key imports.
func assertRSAPrivateKeyEqual(t *testing.T, want, got *rsa.PrivateKey) {
	t.Helper()

	if err := got.Validate(); err != nil {
		t.Fatalf("loaded RSA key is invalid: %v", err)
	}
	if want.E != got.E || want.N.Cmp(got.N) != 0 || want.D.Cmp(got.D) != 0 {
		t.Fatal("loaded RSA public key or private exponent changed")
	}
	if len(want.Primes) != len(got.Primes) {
		t.Fatalf("loaded RSA prime count=%d, want %d", len(got.Primes), len(want.Primes))
	}
	for index := range want.Primes {
		if want.Primes[index].Cmp(got.Primes[index]) != 0 {
			t.Fatalf("loaded RSA prime %d changed", index+1)
		}
	}
}

func TestSignHashesRecoverVerify(t *testing.T) {
	priv, err := Generate("sigkey", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hs HashSet
	for i := range hs.Hash1 {
		hs.Hash1[i] = byte(i)
		hs.Hash2[i] = byte(i + 1)
		hs.Hash3[i] = byte(i + 2)
	}

	sig, err := priv.SignHashes(3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	if sig.Public == nil || sig.Public.Key == nil {
		t.Fatal("signature missing public key")
	}

	if sig.Version != 3 {
		t.Errorf("version: got %d want 3", sig.Version)
	}

	recovered, err := sig.RecoverHashes()
	if err != nil {
		t.Fatalf("RecoverHashes: %v", err)
	}

	if recovered != hs {
		t.Error("recovered hash set != original")
	}

	if err := sig.VerifyHashes(hs); err != nil {
		t.Fatalf("VerifyHashes: %v", err)
	}
}

func TestWriteLoadSignatureRoundtrip(t *testing.T) {
	dir := t.TempDir()

	priv, err := Generate("bisignkey", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hs HashSet
	for i := range hs.Hash1 {
		hs.Hash1[i] = byte(i)
		hs.Hash2[i] = byte(i + 10)
		hs.Hash3[i] = byte(i + 20)
	}

	sig, err := priv.SignHashes(3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	bisignPath := filepath.Join(dir, "file.pbo.test.bisign")
	if err := WriteSignature(bisignPath, sig); err != nil {
		t.Fatalf("WriteSignature: %v", err)
	}

	loaded, err := LoadSignature(bisignPath)
	if err != nil {
		t.Fatalf("LoadSignature: %v", err)
	}

	if loaded.Public.Name != sig.Public.Name {
		t.Errorf("loaded name: got %q want %q", loaded.Public.Name, sig.Public.Name)
	}

	if loaded.Version != sig.Version {
		t.Errorf("loaded version: got %d want %d", loaded.Version, sig.Version)
	}

	recovered, err := loaded.RecoverHashes()
	if err != nil {
		t.Fatalf("RecoverHashes after load: %v", err)
	}

	if recovered != hs {
		t.Error("recovered after roundtrip != original hash set")
	}
}

func TestInMemoryBinaryAPI(t *testing.T) {
	t.Parallel()

	priv, err := Generate("mem", int(MinKeyBits))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privBytes, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}

	privParsed, err := ParsePrivate(privBytes)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}

	if privParsed.Name != priv.Name || privParsed.Key.N.Cmp(priv.Key.N) != 0 {
		t.Fatal("private parse mismatch")
	}

	privReader, err := LoadPrivateFromReader(bytes.NewReader(privBytes))
	if err != nil {
		t.Fatalf("LoadPrivateFromReader: %v", err)
	}
	if privReader.Key.N.Cmp(priv.Key.N) != 0 {
		t.Fatal("private reader mismatch")
	}

	var privBuf bytes.Buffer
	if err := WritePrivateToWriter(&privBuf, priv); err != nil {
		t.Fatalf("WritePrivateToWriter: %v", err)
	}
	if !bytes.Equal(privBuf.Bytes(), privBytes) {
		t.Fatal("private writer bytes mismatch")
	}

	pub := priv.Public()
	pubBytes, err := MarshalPublic(pub)
	if err != nil {
		t.Fatalf("MarshalPublic: %v", err)
	}

	pubParsed, err := ParsePublic(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	if pubParsed.Name != pub.Name || pubParsed.Key.N.Cmp(pub.Key.N) != 0 {
		t.Fatal("public parse mismatch")
	}

	pubReader, err := LoadPublicFromReader(bytes.NewReader(pubBytes))
	if err != nil {
		t.Fatalf("LoadPublicFromReader: %v", err)
	}
	if pubReader.Key.N.Cmp(pub.Key.N) != 0 {
		t.Fatal("public reader mismatch")
	}

	var pubBuf bytes.Buffer
	if err := WritePublicToWriter(&pubBuf, pub); err != nil {
		t.Fatalf("WritePublicToWriter: %v", err)
	}
	if !bytes.Equal(pubBuf.Bytes(), pubBytes) {
		t.Fatal("public writer bytes mismatch")
	}

	var hs HashSet
	for i := range hs.Hash1 {
		hs.Hash1[i] = byte(i)
		hs.Hash2[i] = byte(i + 1)
		hs.Hash3[i] = byte(i + 2)
	}

	sig, err := priv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	sigBytes, err := MarshalSignature(sig)
	if err != nil {
		t.Fatalf("MarshalSignature: %v", err)
	}

	sigParsed, err := ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}

	recovered, err := sigParsed.RecoverHashes()
	if err != nil {
		t.Fatalf("RecoverHashes: %v", err)
	}
	if recovered != hs {
		t.Fatal("signature parse mismatch")
	}

	sigReader, err := LoadSignatureFromReader(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatalf("LoadSignatureFromReader: %v", err)
	}
	if err := sigReader.VerifyHashes(hs); err != nil {
		t.Fatalf("VerifyHashes: %v", err)
	}

	var sigBuf bytes.Buffer
	if err := WriteSignatureToWriter(&sigBuf, sig); err != nil {
		t.Fatalf("WriteSignatureToWriter: %v", err)
	}
	if !bytes.Equal(sigBuf.Bytes(), sigBytes) {
		t.Fatal("signature writer bytes mismatch")
	}
}

func TestGenerateInvalidBits(t *testing.T) {
	_, err := Generate("x", 1000)
	if err == nil {
		t.Fatal("expected error for non-power-of-two bits")
	}
	if !errors.Is(err, ErrInvalidKeyLength) || !errors.Is(err, ErrKeyLengthNotPowerOfTwo) {
		t.Fatalf("expected ErrInvalidKeyLength+ErrKeyLengthNotPowerOfTwo, got: %v", err)
	}

	_, err = Generate("x", 256)
	if err == nil {
		t.Fatal("expected error for bits below minimum")
	}
	if !errors.Is(err, ErrInvalidKeyLength) || !errors.Is(err, ErrKeyLengthTooSmall) {
		t.Fatalf("expected ErrInvalidKeyLength+ErrKeyLengthTooSmall, got: %v", err)
	}

	_, err = Generate("x", 0)
	if err == nil {
		t.Fatal("expected error for zero bits")
	}
	if !errors.Is(err, ErrInvalidKeyLength) || !errors.Is(err, ErrKeyLengthNotPowerOfTwo) {
		t.Fatalf("expected ErrInvalidKeyLength+ErrKeyLengthNotPowerOfTwo, got: %v", err)
	}
}

func TestGenerateMinBitsWorks(t *testing.T) {
	t.Parallel()

	priv, err := Generate("min", int(MinKeyBits))
	if err != nil {
		t.Fatalf("Generate(%d): %v", MinKeyBits, err)
	}

	if priv == nil || priv.Key == nil {
		t.Fatal("expected non-nil private key")
	}

	if got := priv.Key.N.BitLen(); got != int(MinKeyBits) {
		t.Fatalf("unexpected modulus size: got %d want %d", got, MinKeyBits)
	}
}

func TestSignHashesInvalidVersion(t *testing.T) {
	priv, _ := Generate("x", 1024)
	var hs HashSet

	_, err := priv.SignHashes(Version1, hs)
	if err == nil {
		t.Fatal("expected error for version 1")
	}

	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestLoadPrivateInvalidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.biprivatekey")
	// Write a minimal invalid file: name\0, blockSize=0, wrong header
	if err := os.WriteFile(path, []byte("x\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00RSA1"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPrivate(path)
	if err == nil {
		t.Fatal("expected error loading invalid private key")
	}
}

func TestVerifyHashesMismatch(t *testing.T) {
	priv, _ := Generate("v", 1024)
	var hs HashSet
	sig, _ := priv.SignHashes(3, hs)

	var other HashSet
	other.Hash3[0] = 0xff

	err := sig.VerifyHashes(other)
	if err == nil {
		t.Fatal("expected error when hashes do not match")
	}

	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("want ErrVerifyFailed, got %v", err)
	}
}

func TestStrictPKCS1v15VerificationForSupportedKeySizes(t *testing.T) {
	for _, bits := range []int{512, 1024, 2048} {
		t.Run(fmt.Sprintf("%d-bit", bits), func(t *testing.T) {
			priv, err := Generate("verification", bits)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			var hashes HashSet
			for index := range hashes.Hash1 {
				hashes.Hash1[index] = byte(index)
				hashes.Hash2[index] = byte(index + 1)
				hashes.Hash3[index] = byte(index + 2)
			}

			sig, err := priv.SignHashes(Version(3), hashes)
			if err != nil {
				t.Fatalf("SignHashes: %v", err)
			}
			if got, want := len(sig.Block1), priv.Key.Size(); got != want {
				t.Fatalf("signature block size=%d, want %d", got, want)
			}

			recovered, err := sig.RecoverHashes()
			if err != nil {
				t.Fatalf("RecoverHashes: %v", err)
			}
			if recovered != hashes {
				t.Fatalf(
					"recovered hashes=%x/%x/%x, want %x/%x/%x",
					recovered.Hash1, recovered.Hash2, recovered.Hash3, hashes.Hash1, hashes.Hash2, hashes.Hash3,
				)
			}
			if err := sig.VerifyHashes(hashes); err != nil {
				t.Fatalf("VerifyHashes: %v", err)
			}

			if bits >= 1024 {
				signatureBE := reverseReferenceBytes(sig.Block1)
				if err := rsa.VerifyPKCS1v15(
					&priv.Key.PublicKey, crypto.SHA1, hashes.Hash1[:], signatureBE,
				); err != nil {
					t.Fatalf("crypto/rsa VerifyPKCS1v15: %v", err)
				}
			}
		})
	}
}

func TestSmallKeyRejectsMalformedPKCS1v15Blocks(t *testing.T) {
	priv, err := Generate("negative-verification", 512)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hashes HashSet
	hashes.Hash1[0] = 0x12
	hashes.Hash2[0] = 0x34
	hashes.Hash3[0] = 0x56
	valid, err := priv.SignHashes(Version(3), hashes)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	keySize := priv.Key.Size()
	prefix := append([]byte(nil), sha1ASNPrefix...)
	makeMessage := func(paddingSize int, digestInfo []byte, tail []byte) []byte {
		t.Helper()
		message := make([]byte, keySize)
		message[0] = 0
		message[1] = 1
		for index := 2; index < 2+paddingSize; index++ {
			message[index] = 0xff
		}
		separator := 2 + paddingSize
		message[separator] = 0
		copy(message[separator+1:], digestInfo)
		copy(message[separator+1+len(digestInfo):], tail)

		return message
	}

	makeDigestInfo := func(asnPrefix []byte, digest []byte) []byte {
		result := append([]byte(nil), asnPrefix...)
		return append(result, digest...)
	}

	paddingSize := keySize - 3 - len(prefix) - len(hashes.Hash1)
	shortPaddingTail := make([]byte, keySize-3-7-len(prefix)-len(hashes.Hash1))
	wrongPrefix := append([]byte(nil), prefix...)
	wrongPrefix[0] ^= 0x01
	withLeadingGarbage := makeMessage(paddingSize, makeDigestInfo(prefix, hashes.Hash1[:]), nil)
	withLeadingGarbage[0] = 0x7f

	noSeparator := make([]byte, keySize)
	noSeparator[0] = 0
	noSeparator[1] = 1
	for index := 2; index < len(noSeparator); index++ {
		noSeparator[index] = 0xff
	}

	testCases := []struct {
		name         string
		block        []byte
		verifyError  error
		recoverError error
	}{
		{
			name: "short FF padding",
			block: signRawTestMessage(
				t, priv.Key,
				makeMessage(7, makeDigestInfo(prefix, hashes.Hash1[:]), shortPaddingTail),
			),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrPKCS1v15Unpad,
		},
		{
			name:         "missing separator",
			block:        signRawTestMessage(t, priv.Key, noSeparator),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrPKCS1v15Unpad,
		},
		{
			name: "invalid SHA1 prefix",
			block: signRawTestMessage(
				t, priv.Key,
				makeMessage(paddingSize, makeDigestInfo(wrongPrefix, hashes.Hash1[:]), nil),
			),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrPKCS1v15Unpad,
		},
		{
			name: "trailing data after digest",
			block: signRawTestMessage(
				t, priv.Key,
				makeMessage(paddingSize-1, makeDigestInfo(prefix, hashes.Hash1[:]), []byte{0x42}),
			),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrPKCS1v15Unpad,
		},
		{
			block:        signRawTestMessage(t, priv.Key, withLeadingGarbage),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrPKCS1v15Unpad,
		},
		{
			name:         "zero signature integer",
			block:        make([]byte, keySize),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrInvalidSignatureInt,
		},
		{
			name:         "signature integer equals modulus",
			block:        bigIntToReferenceLE(priv.Key.N, keySize),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrInvalidSignatureInt,
		},
		{
			name:         "signature integer exceeds modulus",
			block:        bigIntToReferenceLE(new(big.Int).Add(priv.Key.N, big.NewInt(1)), keySize),
			verifyError:  ErrVerifyFailed,
			recoverError: ErrInvalidSignatureInt,
		},
		{
			name:         "short signature block",
			block:        valid.Block1[:keySize-1],
			verifyError:  ErrSignatureSize,
			recoverError: ErrSignatureSize,
		},
		{
			name:         "long signature block",
			block:        append(append([]byte(nil), valid.Block1...), 0),
			verifyError:  ErrSignatureSize,
			recoverError: ErrSignatureSize,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := *valid
			candidate.Version = Version1
			candidate.Block1 = testCase.block

			verifyErr := candidate.VerifyHashes(hashes)
			if !errors.Is(verifyErr, testCase.verifyError) {
				t.Fatalf("VerifyHashes error=%v, want errors.Is(_, %v)", verifyErr, testCase.verifyError)
			}

			_, recoverErr := candidate.RecoverHashes()
			if !errors.Is(recoverErr, testCase.recoverError) {
				t.Fatalf("RecoverHashes error=%v, want errors.Is(_, %v)", recoverErr, testCase.recoverError)
			}
		})
	}
}

func TestVerifyHashesDigestMismatch(t *testing.T) {
	priv, err := Generate("digest-mismatch", 512)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hashes HashSet
	hashes.Hash1[0] = 0x10
	sig, err := priv.SignHashes(Version(3), hashes)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	wrong := hashes
	wrong.Hash3[0]++
	if err := sig.VerifyHashes(wrong); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("VerifyHashes error=%v, want ErrVerifyFailed", err)
	}

	recovered, err := sig.RecoverHashes()
	if err != nil {
		t.Fatalf("RecoverHashes: %v", err)
	}
	if recovered != hashes {
		t.Fatal("RecoverHashes did not return the embedded digest set")
	}
}

func TestValidateRSAPublicForOpParameterEdges(t *testing.T) {
	validModulus := new(big.Int).Lsh(big.NewInt(1), 511)
	validModulus.Add(validModulus, big.NewInt(1))

	testCases := []struct {
		name string
		key  *rsa.PublicKey
		want error
	}{
		{
			name: "nil key",
			key:  nil,
			want: ErrPublicOpNilPublicKey},
		{
			name: "nil modulus",
			key:  &rsa.PublicKey{E: 65537},
			want: ErrInvalidPublicKey,
		},
		{
			name: "zero modulus",
			key:  &rsa.PublicKey{N: big.NewInt(0), E: 65537},
			want: ErrInvalidPublicKey,
		},
		{
			name: "exponent zero",
			key:  &rsa.PublicKey{N: validModulus, E: 0},
			want: ErrInvalidPublicKey,
		},
		{
			name: "exponent one",
			key:  &rsa.PublicKey{N: validModulus, E: 1},
			want: ErrInvalidPublicKey,
		},
		{
			name: "negative exponent",
			key:  &rsa.PublicKey{N: validModulus, E: -1},
			want: ErrInvalidPublicKey,
		},
		{
			name: "modulus below BI minimum",
			key:  &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 510), E: 65537},
			want: ErrInvalidPublicKey,
		},
		{
			name: "modulus above parser limit",
			key:  &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), MaxKeyBits), E: 65537},
			want: ErrInvalidPublicKey,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateRSAPublicForOp(testCase.key); !errors.Is(err, testCase.want) {
				t.Fatalf("validateRSAPublicForOp error=%v, want errors.Is(_, %v)", err, testCase.want)
			}
		})
	}
}

// signRawTestMessage creates malformed RSA test vectors with a private test key.
func signRawTestMessage(t *testing.T, key *rsa.PrivateKey, encoded []byte) []byte {
	t.Helper()

	if len(encoded) != key.Size() {
		t.Fatalf("raw message length=%d, want %d", len(encoded), key.Size())
	}
	representative := new(big.Int).SetBytes(encoded)
	if representative.Cmp(key.N) >= 0 {
		t.Fatal("raw message is outside the RSA modulus")
	}

	signature := new(big.Int).Exp(representative, key.D, key.N)
	return bigIntToReferenceLE(signature, key.Size())
}

// bigIntToReferenceLE encodes an integer as a fixed-width BI little-endian block.
func bigIntToReferenceLE(value *big.Int, size int) []byte {
	encodedBE := make([]byte, size)
	value.FillBytes(encodedBE)

	return reverseReferenceBytes(encodedBE)
}

func TestWritePrivateInvalidKeyReturnsError(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("WritePrivate panicked: %v", recovered)
		}
	}()

	err := WritePrivate(
		filepath.Join(t.TempDir(), "bad.biprivatekey"),
		&PrivateKeyFile{Name: "bad", Key: &rsa.PrivateKey{}},
	)
	if err == nil || !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey, got: %v", err)
	}
}

func TestWritePublicInvalidKeyReturnsError(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("WritePublic panicked: %v", recovered)
		}
	}()

	err := WritePublic(
		filepath.Join(t.TempDir(), "bad.bikey"),
		&PublicKeyFile{Name: "bad", Key: &rsa.PublicKey{}},
	)
	if err == nil || !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("expected ErrInvalidPublicKey, got: %v", err)
	}
}

func TestPublicParserRejectsInvalidExponents(t *testing.T) {
	priv, err := Generate("invalid-exponent", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := MarshalPublic(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPublic: %v", err)
	}

	nameEnd := bytes.IndexByte(data, 0)
	if nameEnd < 0 {
		t.Fatal("serialized public key has no name terminator")
	}

	exponentOffset := nameEnd + 1 + 4 + 12 + 4
	for _, exponent := range []uint32{0, 1} {
		invalid := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(invalid[exponentOffset:exponentOffset+4], exponent)

		if _, err := ParsePublic(invalid); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParsePublic exponent %d error=%v, want ErrInvalidPublicKey", exponent, err)
		}
	}
}

func TestRSAExponentMustFitBIField(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("an exponent outside uint32 requires a 64-bit int")
	}

	priv, err := Generate("wide-exponent", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	wideExponentValue := uint64(^uint32(0))
	wideExponentValue++
	wideExponent := int(wideExponentValue)
	pub := *priv.Public().Key
	pub.E = wideExponent
	if _, err := MarshalPublic(&PublicKeyFile{
		Name: priv.Name,
		Key:  &pub,
	}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("MarshalPublic error=%v, want ErrInvalidPublicKey", err)
	}

	privateKey := *priv.Key
	privateKey.E = wideExponent
	if _, err := MarshalPrivate(&PrivateKeyFile{
		Name: priv.Name,
		Key:  &privateKey,
	}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("MarshalPrivate error=%v, want ErrInvalidPrivateKey", err)
	}
	if _, err := (&PrivateKeyFile{
		Name: priv.Name,
		Key:  &privateKey,
	}).SignHashes(Version3, HashSet{}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("SignHashes error=%v, want ErrInvalidPrivateKey", err)
	}
}

func TestPrivateKeyExportRejectsUnsupportedPrimeLayout(t *testing.T) {
	t.Parallel()

	t.Run("unequal prime widths", func(t *testing.T) {
		var key *rsa.PrivateKey

		for key == nil {
			p, err := rand.Prime(rand.Reader, 300)
			if err != nil {
				t.Fatalf("generate P: %v", err)
			}

			q, err := rand.Prime(rand.Reader, 212)
			if err != nil {
				t.Fatalf("generate Q: %v", err)
			}

			n := new(big.Int).Mul(p, q)
			if n.BitLen() != 512 {
				continue
			}

			const exponent = 65537
			phi := new(big.Int).Mul(
				new(big.Int).Sub(p, big.NewInt(1)),
				new(big.Int).Sub(q, big.NewInt(1)),
			)
			d := new(big.Int).ModInverse(big.NewInt(exponent), phi)
			if d == nil {
				continue
			}

			candidate := &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{N: n, E: exponent},
				D:         d,
				Primes:    []*big.Int{p, q},
			}
			candidate.Precompute()
			if candidate.Validate() == nil {
				key = candidate
			}
		}

		if _, err := FromRSAPrivate("unequal-primes", key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("FromRSAPrivate error=%v, want ErrInvalidPrivateKey", err)
		}
		if _, err := MarshalPrivate(&PrivateKeyFile{Name: "unequal-primes", Key: key}); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("MarshalPrivate error=%v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("multiple primes", func(t *testing.T) {
		key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 1024)
		if err != nil {
			t.Fatalf("GenerateMultiPrimeKey: %v", err)
		}

		if _, err := FromRSAPrivate("multi-prime", key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("FromRSAPrivate error=%v, want ErrInvalidPrivateKey", err)
		}
		if _, err := MarshalPrivate(&PrivateKeyFile{Name: "multi-prime", Key: key}); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("MarshalPrivate error=%v, want ErrInvalidPrivateKey", err)
		}
	})
}

func TestPrivateKeyExportRejectsOversizedPrivateExponent(t *testing.T) {
	t.Parallel()

	generated, err := Generate("oversized-private-exponent", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	pMinusOne := new(big.Int).Sub(generated.Key.Primes[0], big.NewInt(1))
	qMinusOne := new(big.Int).Sub(generated.Key.Primes[1], big.NewInt(1))
	phi := new(big.Int).Mul(pMinusOne, qMinusOne)
	wideKey := *generated.Key
	wideKey.D = new(big.Int).Add(
		generated.Key.D,
		new(big.Int).Mul(phi, big.NewInt(4)),
	)
	wideKey.Precomputed = rsa.PrecomputedValues{}
	if wideKey.D.BitLen() <= wideKey.N.BitLen() {
		t.Fatalf(
			"private exponent bit length=%d, want greater than modulus bit length=%d",
			wideKey.D.BitLen(), wideKey.N.BitLen(),
		)
	}

	for _, prime := range wideKey.Primes {
		primeMinusOne := new(big.Int).Sub(prime, big.NewInt(1))
		product := new(big.Int).Mul(big.NewInt(int64(wideKey.E)), wideKey.D)
		if product.Mod(product, primeMinusOne).Cmp(big.NewInt(1)) != 0 {
			t.Fatal("oversized private exponent does not satisfy the RSA exponent relation")
		}
	}

	if _, err := FromRSAPrivate(
		"oversized-private-exponent", &wideKey,
	); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("FromRSAPrivate error=%v, want ErrInvalidPrivateKey", err)
	}

	if _, err := MarshalPrivate(&PrivateKeyFile{
		Name: "oversized-private-exponent",
		Key:  &wideKey,
	}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("MarshalPrivate error=%v, want ErrInvalidPrivateKey", err)
	}
}

func TestWriteReversedBigIntRejectsTruncation(t *testing.T) {
	var buf bytes.Buffer
	err := writeReversedBigInt(&buf, big.NewInt(256), 1)
	if !errors.Is(err, ErrIntegerDoesNotFitField) {
		t.Fatalf("writeReversedBigInt error=%v, want ErrIntegerDoesNotFitField", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("writeReversedBigInt wrote %d bytes before rejecting the value", buf.Len())
	}
}

func TestWriterAPIsReturnErrShortWrite(t *testing.T) {
	priv, err := Generate("short-write", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sig, err := priv.SignHashes(Version3, HashSet{})
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	testCases := []struct {
		name  string
		write func(io.Writer) error
	}{
		{name: "public key", write: func(w io.Writer) error { return WritePublicToWriter(w, priv.Public()) }},
		{name: "private key", write: func(w io.Writer) error { return WritePrivateToWriter(w, priv) }},
		{name: "signature", write: func(w io.Writer) error { return WriteSignatureToWriter(w, sig) }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.write(shortWriter{}); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("write error=%v, want io.ErrShortWrite", err)
			}
		})
	}
}

func TestMarshalRejectsEmbeddedNULKeyNames(t *testing.T) {
	priv, err := Generate("embedded-nul", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	private := *priv
	private.Name = "invalid\x00name"
	public := *priv.Public()
	public.Name = private.Name
	sig, err := priv.SignHashes(Version3, HashSet{})
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	sig.Public.Name = private.Name
	if _, err := MarshalPrivate(&private); !errors.Is(err, ErrInvalidKeyName) {
		t.Errorf("MarshalPrivate error=%v, want ErrInvalidKeyName", err)
	}
	if _, err := MarshalPublic(&public); !errors.Is(err, ErrInvalidKeyName) {
		t.Errorf("MarshalPublic error=%v, want ErrInvalidKeyName", err)
	}
	if _, err := MarshalSignature(sig); !errors.Is(err, ErrInvalidKeyName) {
		t.Errorf("MarshalSignature error=%v, want ErrInvalidKeyName", err)
	}
}

func TestModulusSHA256InvalidKey(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ModulusSHA256 panicked: %v", recovered)
		}
	}()

	if got := ModulusSHA256(&rsa.PublicKey{}); got != "" {
		t.Fatalf("expected empty digest for invalid key, got: %q", got)
	}
}

func TestInspectDetectsSupportedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	priv, err := Generate("inspect-key", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privPath := filepath.Join(dir, "inspect-key.biprivatekey")
	pubPath := filepath.Join(dir, "inspect-key.bikey")
	sigPath := filepath.Join(dir, "file.pbo.inspect-key.bisign")

	if err := WritePrivate(privPath, priv); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}

	if err := WritePublic(pubPath, priv.Public()); err != nil {
		t.Fatalf("WritePublic: %v", err)
	}

	var hs HashSet
	sig, err := priv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}
	if err := WriteSignature(sigPath, sig); err != nil {
		t.Fatalf("WriteSignature: %v", err)
	}

	pubInfo, err := Inspect(pubPath)
	if err != nil {
		t.Fatalf("Inspect(pub): %v", err)
	}
	if pubInfo == nil || pubInfo.Key == nil || pubInfo.Signature != nil {
		t.Fatalf("unexpected inspect result for public key: %#v", pubInfo)
	}

	privInfo, err := Inspect(privPath)
	if err != nil {
		t.Fatalf("Inspect(priv): %v", err)
	}
	if privInfo == nil || privInfo.Key == nil || privInfo.Signature != nil {
		t.Fatalf("unexpected inspect result for private key: %#v", privInfo)
	}

	sigInfo, err := Inspect(sigPath)
	if err != nil {
		t.Fatalf("Inspect(sig): %v", err)
	}
	if sigInfo == nil || sigInfo.Signature == nil || sigInfo.Key != nil {
		t.Fatalf("unexpected inspect result for signature: %#v", sigInfo)
	}
}

func TestInspectUnsupportedExtension(t *testing.T) {
	t.Parallel()

	_, err := Inspect(filepath.Join(t.TempDir(), "unsupported.txt"))
	if err == nil || !errors.Is(err, ErrUnsupportedPublicSource) {
		t.Fatalf("expected ErrUnsupportedPublicSource, got: %v", err)
	}
}

func TestWriteSignatureValidatesBlockSize(t *testing.T) {
	t.Parallel()

	priv, err := Generate("sig-check", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hs HashSet
	sig, err := priv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	sig.Block1 = sig.Block1[:len(sig.Block1)-1]
	err = WriteSignature(filepath.Join(t.TempDir(), "bad.bisign"), sig)
	if err == nil || !errors.Is(err, ErrSignatureSize) {
		t.Fatalf("expected ErrSignatureSize, got: %v", err)
	}
}

func TestWriteSignatureRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	priv, err := Generate("sig-version", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hs HashSet
	sig, err := priv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	sig.Version = Version(99)
	err = WriteSignature(filepath.Join(t.TempDir(), "bad-version.bisign"), sig)
	if err == nil || !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

func TestV1SignatureRoundtripAndUnsupportedVersions(t *testing.T) {
	t.Parallel()

	priv, err := Generate("sig-load-version", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hs HashSet
	sig, err := priv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	data, err := serializeSignature(sig)
	if err != nil {
		t.Fatalf("serializeSignature: %v", err)
	}

	pubData, err := serializePublic(sig.Public)
	if err != nil {
		t.Fatalf("serializePublic: %v", err)
	}

	versionOffset := len(pubData) + 4 + len(sig.Block1)
	if versionOffset+4 > len(data) {
		t.Fatalf("invalid version offset: %d len=%d", versionOffset, len(data))
	}

	// The V1 fixture is synthetic: the signer creates V2/V3,
	// so only the version field is changed while the three-block layout stays intact.
	binary.LittleEndian.PutUint32(data[versionOffset:versionOffset+4], uint32(Version1))
	loaded, err := ParseSignature(data)
	if err != nil {
		t.Fatalf("ParseSignature V1: %v", err)
	}
	if loaded.Version != Version1 {
		t.Fatalf("version=%d, want %d", loaded.Version, Version1)
	}
	if got, want := len(loaded.Block1), sig.Public.Key.Size(); got != want {
		t.Fatalf("Block1 size=%d, want %d", got, want)
	}
	if got, want := len(loaded.Block2), sig.Public.Key.Size(); got != want {
		t.Fatalf("Block2 size=%d, want %d", got, want)
	}
	if got, want := len(loaded.Block3), sig.Public.Key.Size(); got != want {
		t.Fatalf("Block3 size=%d, want %d", got, want)
	}

	encoded, err := MarshalSignature(loaded)
	if err != nil {
		t.Fatalf("MarshalSignature V1: %v", err)
	}
	if !bytes.Equal(encoded, data) {
		t.Fatal("V1 signature changed during parse/marshal roundtrip")
	}
	if err := loaded.VerifyHashes(HashSet{}); err != nil {
		t.Fatalf("VerifyHashes V1: %v", err)
	}

	for _, invalidVersion := range []uint32{0, 4, ^uint32(0)} {
		invalid := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(invalid[versionOffset:versionOffset+4], invalidVersion)

		if _, err := ParseSignature(invalid); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("ParseSignature version %d error=%v, want ErrUnsupportedVersion", invalidVersion, err)
		}
	}
}

func TestVerifyHashesUsesVersionSelectedBlock(t *testing.T) {
	priv, err := Generate("version-selection", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var hashes HashSet
	for index := range hashes.Hash1 {
		hashes.Hash1[index] = byte(index)
		hashes.Hash2[index] = byte(index + 1)
		hashes.Hash3[index] = byte(index + 2)
	}

	for _, version := range []Version{Version1, Version2, Version3} {
		t.Run(fmt.Sprintf("version %d", version), func(t *testing.T) {
			signVersion := version
			if signVersion == Version1 {
				// The BI signer does not emit V1, so use its V2 blocks for this synthetic case.
				signVersion = Version2
			}
			sig, err := priv.SignHashes(signVersion, hashes)
			if err != nil {
				t.Fatalf("SignHashes: %v", err)
			}
			sig.Version = version

			invalidBlock := make([]byte, priv.Key.Size())
			if version != Version1 {
				sig.Block1 = invalidBlock
			}
			if version != Version2 {
				sig.Block2 = invalidBlock
			}
			if version != Version3 {
				sig.Block3 = invalidBlock
			}

			if err := sig.VerifyHashes(hashes); err != nil {
				t.Fatalf("VerifyHashes with invalid unselected blocks: %v", err)
			}
			if _, err := sig.RecoverHashes(); err == nil {
				t.Fatal("RecoverHashes accepted an invalid signature block")
			}

			invalidSelectedBlock := *sig
			invalidSelectedBlock.Block1 = append([]byte(nil), sig.Block1...)
			invalidSelectedBlock.Block2 = append([]byte(nil), sig.Block2...)
			invalidSelectedBlock.Block3 = append([]byte(nil), sig.Block3...)
			switch version {
			case Version1:
				invalidSelectedBlock.Block1[0] ^= 0xff
			case Version2:
				invalidSelectedBlock.Block2[0] ^= 0xff
			case Version3:
				invalidSelectedBlock.Block3[0] ^= 0xff
			}
			if err := invalidSelectedBlock.VerifyHashes(hashes); !errors.Is(err, ErrVerifyFailed) {
				t.Fatalf("VerifyHashes error=%v, want ErrVerifyFailed", err)
			}
		})
	}
}

func TestGeneratedBinaryRoundtripStability(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	priv, err := Generate("stable-key", 1024)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privA := filepath.Join(dir, "stable-key.a.biprivatekey")
	privB := filepath.Join(dir, "stable-key.b.biprivatekey")
	if err := WritePrivate(privA, priv); err != nil {
		t.Fatalf("WritePrivate A: %v", err)
	}

	loadedPriv, err := LoadPrivate(privA)
	if err != nil {
		t.Fatalf("LoadPrivate A: %v", err)
	}

	if err := WritePrivate(privB, loadedPriv); err != nil {
		t.Fatalf("WritePrivate B: %v", err)
	}

	assertFileBytesEqual(t, privA, privB, "private roundtrip bytes")

	pubA := filepath.Join(dir, "stable-key.a.bikey")
	pubB := filepath.Join(dir, "stable-key.b.bikey")
	if err := WritePublic(pubA, loadedPriv.Public()); err != nil {
		t.Fatalf("WritePublic A: %v", err)
	}

	loadedPub, err := LoadPublic(pubA)
	if err != nil {
		t.Fatalf("LoadPublic A: %v", err)
	}

	if err := WritePublic(pubB, loadedPub); err != nil {
		t.Fatalf("WritePublic B: %v", err)
	}

	assertFileBytesEqual(t, pubA, pubB, "public roundtrip bytes")

	var hs HashSet
	for i := range hs.Hash1 {
		hs.Hash1[i] = byte(i)
		hs.Hash2[i] = byte(i + 10)
		hs.Hash3[i] = byte(i + 20)
	}

	sig, err := loadedPriv.SignHashes(Version3, hs)
	if err != nil {
		t.Fatalf("SignHashes: %v", err)
	}

	sigA := filepath.Join(dir, "file.pbo.stable.a.bisign")
	sigB := filepath.Join(dir, "file.pbo.stable.b.bisign")
	if err := WriteSignature(sigA, sig); err != nil {
		t.Fatalf("WriteSignature A: %v", err)
	}

	loadedSig, err := LoadSignature(sigA)
	if err != nil {
		t.Fatalf("LoadSignature A: %v", err)
	}

	if err := WriteSignature(sigB, loadedSig); err != nil {
		t.Fatalf("WriteSignature B: %v", err)
	}

	assertFileBytesEqual(t, sigA, sigB, "signature roundtrip bytes")
}

func TestFixtureBinaryRoundtripStability(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("testdata", "canonical")

	for _, key := range []struct {
		game string
		name string
	}{
		{game: "dayz", name: "BisignDayZReference"},
		{game: "arma", name: "BisignArmaReference"},
	} {
		keyDir := filepath.Join(fixtureDir, key.game, "keys")
		assertPrivateFixtureRoundtripStable(t, filepath.Join(keyDir, key.name+ExtBIPrivateKey))
		assertPublicFixtureRoundtripStable(t, filepath.Join(keyDir, key.name+ExtBIKey))
	}

	for _, name := range []string{"dayz-v2", "dayz-v3", "arma-v2", "arma-v3"} {
		game := strings.Split(name, "-")[0]
		path := filepath.Join(fixtureDir, game, "signatures", name+ExtBISign)
		assertSignatureFixtureRoundtripStable(t, path)
	}
}

// assertFileBytesEqual compares two files byte-for-byte.
func assertFileBytesEqual(t *testing.T, leftPath string, rightPath string, title string) {
	t.Helper()

	left, err := os.ReadFile(leftPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", leftPath, err)
	}

	right, err := os.ReadFile(rightPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", rightPath, err)
	}

	if !bytes.Equal(left, right) {
		t.Fatalf("%s mismatch: %s != %s", title, leftPath, rightPath)
	}
}

// assertPrivateFixtureRoundtripStable ensures .biprivatekey fixture is byte-stable on load/write.
func assertPrivateFixtureRoundtripStable(t *testing.T, fixturePath string) {
	t.Helper()

	loaded, err := LoadPrivate(fixturePath)
	if err != nil {
		t.Fatalf("LoadPrivate fixture: %v", err)
	}

	out := filepath.Join(t.TempDir(), filepath.Base(fixturePath))
	if err := WritePrivate(out, loaded); err != nil {
		t.Fatalf("WritePrivate fixture copy: %v", err)
	}

	assertFileBytesEqual(t, fixturePath, out, "private fixture roundtrip bytes")
}

// assertPublicFixtureRoundtripStable ensures .bikey fixture is byte-stable on load/write.
func assertPublicFixtureRoundtripStable(t *testing.T, fixturePath string) {
	t.Helper()

	loaded, err := LoadPublic(fixturePath)
	if err != nil {
		t.Fatalf("LoadPublic fixture: %v", err)
	}

	out := filepath.Join(t.TempDir(), filepath.Base(fixturePath))
	if err := WritePublic(out, loaded); err != nil {
		t.Fatalf("WritePublic fixture copy: %v", err)
	}

	assertFileBytesEqual(t, fixturePath, out, "public fixture roundtrip bytes")
}

// assertSignatureFixtureRoundtripStable ensures .bisign fixture is byte-stable on load/write.
func assertSignatureFixtureRoundtripStable(t *testing.T, fixturePath string) {
	t.Helper()

	loaded, err := LoadSignature(fixturePath)
	if err != nil {
		t.Fatalf("LoadSignature fixture: %v", err)
	}

	out := filepath.Join(t.TempDir(), filepath.Base(fixturePath))
	if err := WriteSignature(out, loaded); err != nil {
		t.Fatalf("WriteSignature fixture copy: %v", err)
	}

	assertFileBytesEqual(t, fixturePath, out, "signature fixture roundtrip bytes")
}

// TestOriginalToolCorpusIntegrity verifies each asset against its manifest digest.
func TestOriginalToolCorpusIntegrity(t *testing.T) {
	t.Parallel()

	var manifest struct {
		Assets []struct {
			Path   string `json:"path"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"assets"`
	}

	fixtureDir := filepath.Join("testdata", "canonical")
	manifestBytes, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}

	for _, asset := range manifest.Assets {
		t.Run(asset.Path, func(t *testing.T) {
			t.Parallel()

			if filepath.IsAbs(asset.Path) || strings.Contains(asset.Path, ":") {
				t.Fatalf("asset path must be relative: %q", asset.Path)
			}

			path := filepath.Join(fixtureDir, filepath.FromSlash(asset.Path))
			relative, err := filepath.Rel(fixtureDir, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				t.Fatalf("asset path escapes corpus: %q", asset.Path)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read corpus asset %q: %v", asset.Path, err)
			}
			if int64(len(data)) != asset.Size {
				t.Fatalf("asset %q size=%d, want %d", asset.Path, len(data), asset.Size)
			}

			digest := sha256.Sum256(data)
			if got := hex.EncodeToString(digest[:]); got != asset.SHA256 {
				t.Fatalf("asset %q SHA-256=%s, want %s", asset.Path, got, asset.SHA256)
			}
		})
	}
}

// TestOriginalToolSignatureFixtures validates original signatures against independent hash vectors.
func TestOriginalToolSignatureFixtures(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("testdata", "canonical")
	var manifest struct {
		Keys map[string]struct {
			Authority   string `json:"authority"`
			RSABits     int    `json:"rsa_bits"`
			RSAExponent int    `json:"rsa_exponent"`
			PublicKey   struct {
				Path string `json:"path"`
			} `json:"public_key"`
			PrivateKey struct {
				Path string `json:"path"`
			} `json:"private_key"`
		} `json:"keys"`
		Signatures map[string]struct {
			GameType        string  `json:"game_type"`
			Version         Version `json:"version"`
			Path            string  `json:"path"`
			ReferenceHashes struct {
				Hash1 string `json:"hash1"`
				Hash2 string `json:"hash2"`
				Hash3 string `json:"hash3"`
			} `json:"reference_hashes"`
		} `json:"signatures"`
	}
	manifestBytes, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}

	privateKeys := make(map[string]*PrivateKeyFile, len(manifest.Keys))
	publicKeys := make(map[string]*PublicKeyFile, len(manifest.Keys))
	for game, key := range manifest.Keys {
		private, err := LoadPrivate(
			filepath.Join(fixtureDir, filepath.FromSlash(key.PrivateKey.Path)),
		)
		if err != nil {
			t.Fatalf("LoadPrivate %s key: %v", game, err)
		}

		public, err := LoadPublic(
			filepath.Join(fixtureDir, filepath.FromSlash(key.PublicKey.Path)),
		)
		if err != nil {
			t.Fatalf("LoadPublic %s key: %v", game, err)
		}

		if private.Name != key.Authority || public.Name != key.Authority {
			t.Fatalf(
				"%s key authority mismatch: private=%q public=%q want=%q",
				game, private.Name, public.Name, key.Authority,
			)
		}
		if private.Key.N.Cmp(public.Key.N) != 0 || private.Key.E != public.Key.E {
			t.Fatalf(
				"%s public and private key material does not match",
				game,
			)
		}
		if private.Key.N.BitLen() != key.RSABits || private.Key.E != key.RSAExponent {
			t.Fatalf(
				"%s RSA metadata mismatch: bits=%d exponent=%d",
				game, private.Key.N.BitLen(), private.Key.E,
			)
		}

		privateKeys[game] = private
		publicKeys[game] = public
	}

	for _, name := range []string{"dayz-v2", "dayz-v3", "arma-v2", "arma-v3"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture, ok := manifest.Signatures[name]
			if !ok {
				t.Fatalf("signature %q missing from manifest", name)
			}

			bisignPath := filepath.Join(fixtureDir, filepath.FromSlash(fixture.Path))
			sig, err := LoadSignature(bisignPath)
			if err != nil {
				t.Fatalf("LoadSignature: %v", err)
			}
			if sig.Version != fixture.Version {
				t.Fatalf("signature version=%d, want %d", sig.Version, fixture.Version)
			}

			public := publicKeys[fixture.GameType]
			if public == nil || sig.Public.Name != public.Name || sig.Public.Key.N.Cmp(public.Key.N) != 0 {
				t.Fatal("embedded public identity does not match the game's BI key")
			}

			want := HashSet{
				Hash1: mustDecodeReferenceHash(t, fixture.ReferenceHashes.Hash1),
				Hash2: mustDecodeReferenceHash(t, fixture.ReferenceHashes.Hash2),
				Hash3: mustDecodeReferenceHash(t, fixture.ReferenceHashes.Hash3),
			}

			originalBytes, err := os.ReadFile(bisignPath)
			if err != nil {
				t.Fatalf("read original signature: %v", err)
			}
			independent, err := decodeReferenceSignature(originalBytes)
			if err != nil {
				t.Fatalf("independent signature decoding: %v", err)
			}
			key := manifest.Keys[fixture.GameType]
			if independent.Version != fixture.Version || independent.KeyName != key.Authority {
				t.Fatal("independent decoder found unexpected signature metadata")
			}
			if independent.RSABits != key.RSABits || independent.RSAExponent != key.RSAExponent {
				t.Fatal("independent decoder found unexpected RSA metadata")
			}
			if independent.Hashes != want {
				t.Fatal("manifest hashes differ from independent signature decoding")
			}

			got, err := sig.RecoverHashes()
			if err != nil {
				t.Fatalf("RecoverHashes: %v", err)
			}
			if got != want {
				t.Fatalf(
					"recovered hashes=%x/%x/%x, want %x/%x/%x",
					got.Hash1, got.Hash2, got.Hash3, want.Hash1, want.Hash2, want.Hash3,
				)
			}
			if err := sig.VerifyHashes(want); err != nil {
				t.Fatalf("VerifyHashes: %v", err)
			}

			recreated, err := privateKeys[fixture.GameType].SignHashes(fixture.Version, want)
			if err != nil {
				t.Fatalf("SignHashes: %v", err)
			}
			if !bytes.Equal(recreated.Block1, sig.Block1) ||
				!bytes.Equal(recreated.Block2, sig.Block2) ||
				!bytes.Equal(recreated.Block3, sig.Block3) {
				t.Fatal("SignHashes output differs from original signature blocks")
			}

			recreatedBytes, err := MarshalSignature(recreated)
			if err != nil {
				t.Fatalf("MarshalSignature: %v", err)
			}
			if !bytes.Equal(recreatedBytes, originalBytes) {
				t.Fatal("recreated signature differs byte-for-byte from original output")
			}
		})
	}
}

// referenceSignature stores fields decoded without using the package's parser.
type referenceSignature struct {
	KeyName     string  // Embedded BI authority name.
	Version     Version // Stored signature format version.
	RSABits     int     // RSA modulus width in bits.
	RSAExponent int     // RSA public exponent.
	Hashes      HashSet // SHA-1 values recovered from the signature blocks.
}

// shortWriter violates io.Writer's full-write contract for regression testing.
type shortWriter struct{}

// Write reports a short write without an error.
func (shortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	return len(data) - 1, nil
}

// decodeReferenceSignature reads BI fields and recovers all three hashes independently.
func decodeReferenceSignature(data []byte) (referenceSignature, error) {
	var result referenceSignature

	nameEnd := bytes.IndexByte(data, 0)
	if nameEnd <= 0 {
		return result, errors.New("missing BI key name")
	}

	result.KeyName = string(data[:nameEnd])
	offset := nameEnd + 1
	blockSize, err := readReferenceUint32(data, &offset)
	if err != nil {
		return result, err
	}
	if len(data)-offset < 12 {
		return result, errors.New("truncated BI public key header")
	}

	offset += 8
	if string(data[offset:offset+4]) != "RSA1" {
		return result, errors.New("unexpected BI RSA key tag")
	}

	offset += 4
	bits, err := readReferenceUint32(data, &offset)
	if err != nil {
		return result, err
	}

	exponent, err := readReferenceUint32(data, &offset)
	if err != nil {
		return result, err
	}
	if bits == 0 || bits%8 != 0 || exponent < 3 {
		return result, errors.New("invalid RSA public key parameters")
	}

	keySize := int(bits / 8)
	if blockSize != uint32(20+keySize) {
		return result, errors.New("BI public key block size mismatch")
	}

	modulusLE, err := readReferenceBytes(data, &offset, keySize)
	if err != nil {
		return result, err
	}

	result.RSABits = int(bits)
	result.RSAExponent = int(exponent)

	block1, err := readReferenceSignatureBlock(data, &offset, keySize)
	if err != nil {
		return result, err
	}

	version, err := readReferenceUint32(data, &offset)
	if err != nil {
		return result, err
	}

	result.Version = Version(version)
	block2, err := readReferenceSignatureBlock(data, &offset, keySize)
	if err != nil {
		return result, err
	}

	block3, err := readReferenceSignatureBlock(data, &offset, keySize)
	if err != nil {
		return result, err
	}
	if offset != len(data) {
		return result, errors.New("unexpected bytes after signature blocks")
	}

	result.Hashes.Hash1, err = decodeReferenceSignatureBlock(block1, modulusLE, exponent)
	if err != nil {
		return result, err
	}

	result.Hashes.Hash2, err = decodeReferenceSignatureBlock(block2, modulusLE, exponent)
	if err != nil {
		return result, err
	}

	result.Hashes.Hash3, err = decodeReferenceSignatureBlock(block3, modulusLE, exponent)
	if err != nil {
		return result, err
	}

	return result, nil
}

// readReferenceSignatureBlock reads a fixed-width little-endian RSA block.
func readReferenceSignatureBlock(data []byte, offset *int, keySize int) ([]byte, error) {
	length, err := readReferenceUint32(data, offset)
	if err != nil {
		return nil, err
	}
	if int(length) != keySize {
		return nil, errors.New("RSA signature block length mismatch")
	}

	return readReferenceBytes(data, offset, keySize)
}

// decodeReferenceSignatureBlock applies RSA public exponentiation and strict PKCS#1 v1.5 decoding.
func decodeReferenceSignatureBlock(blockLE, modulusLE []byte, exponent uint32) ([20]byte, error) {
	var digest [20]byte
	blockBE := reverseReferenceBytes(blockLE)
	modulusBE := reverseReferenceBytes(modulusLE)
	signature := new(big.Int).SetBytes(blockBE)
	modulus := new(big.Int).SetBytes(modulusBE)
	if signature.Sign() <= 0 || signature.Cmp(modulus) >= 0 {
		return digest, errors.New("RSA signature value is out of range")
	}

	encodedInt := new(big.Int).Exp(signature, new(big.Int).SetUint64(uint64(exponent)), modulus)
	if len(encodedInt.Bytes()) > len(blockLE) {
		return digest, errors.New("recovered RSA message exceeds modulus width")
	}

	encoded := make([]byte, len(blockLE))
	encodedInt.FillBytes(encoded)
	if len(encoded) < 2 || encoded[0] != 0 || encoded[1] != 1 {
		return digest, errors.New("invalid PKCS#1 v1.5 block header")
	}

	separator := 2
	for separator < len(encoded) && encoded[separator] == 0xff {
		separator++
	}
	if separator-2 < 8 || separator >= len(encoded) || encoded[separator] != 0 {
		return digest, errors.New("invalid PKCS#1 v1.5 padding")
	}

	separator++
	prefix := []byte{
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
	}
	if len(encoded)-separator != len(prefix)+len(digest) ||
		!bytes.Equal(encoded[separator:separator+len(prefix)], prefix) {
		return digest, errors.New("invalid SHA-1 DigestInfo")
	}

	copy(digest[:], encoded[separator+len(prefix):])
	return digest, nil
}

// readReferenceUint32 reads one bounded little-endian uint32 from raw fixture bytes.
func readReferenceUint32(data []byte, offset *int) (uint32, error) {
	if *offset < 0 || len(data)-*offset < 4 {
		return 0, errors.New("truncated uint32 field")
	}

	value := binary.LittleEndian.Uint32(data[*offset : *offset+4])
	*offset += 4

	return value, nil
}

// readReferenceBytes returns a copy of one bounded byte range.
func readReferenceBytes(data []byte, offset *int, size int) ([]byte, error) {
	if size < 0 || *offset < 0 || len(data)-*offset < size {
		return nil, errors.New("truncated byte field")
	}

	result := append([]byte(nil), data[*offset:*offset+size]...)
	*offset += size

	return result, nil
}

// reverseReferenceBytes returns a copy of data in reverse order.
func reverseReferenceBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for index := range data {
		result[len(data)-1-index] = data[index]
	}

	return result
}

// mustDecodeReferenceHash parses one 20-byte SHA-1 vector from the manifest.
func mustDecodeReferenceHash(t *testing.T, value string) [20]byte {
	t.Helper()

	var result [20]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hash vector %q: %v", value, err)
	}
	if len(decoded) != len(result) {
		t.Fatalf("hash vector length=%d, want %d", len(decoded), len(result))
	}

	copy(result[:], decoded)
	return result
}
