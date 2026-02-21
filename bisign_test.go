package bisign

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
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

	_, err := priv.SignHashes(1, hs)
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
	other.Hash1[0] = 0xff

	err := sig.VerifyHashes(other)
	if err == nil {
		t.Fatal("expected error when hashes do not match")
	}

	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("want ErrVerifyFailed, got %v", err)
	}
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

func TestLoadSignatureRejectsUnsupportedVersion(t *testing.T) {
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

	binary.LittleEndian.PutUint32(data[versionOffset:versionOffset+4], 1)
	path := filepath.Join(t.TempDir(), "unsupported-version.bisign")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = LoadSignature(path)
	if err == nil || !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", err)
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

	privPath := "../pbo/pkg/bikey/test_data/dsutils.biprivatekey"
	pubPath := "../pbo/pkg/bikey/test_data/dsutils.bikey"
	sigPath := "../pbo/pkg/bikey/test_data/bin.pbo.dayz.bisign"

	if _, err := os.Stat(privPath); err != nil {
		t.Skipf("fixture not found: %s", privPath)
	}

	assertPrivateFixtureRoundtripStable(t, privPath)
	assertPublicFixtureRoundtripStable(t, pubPath)

	if _, err := os.Stat(sigPath); err == nil {
		assertSignatureFixtureRoundtripStable(t, sigPath)
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

// TestInteropPboFixture loads key/signature from pbo prototype test_data if present.
func TestInteropPboFixture(t *testing.T) {
	privPath := "../pbo/pkg/bikey/test_data/dsutils.biprivatekey"
	pubPath := "../pbo/pkg/bikey/test_data/dsutils.bikey"
	bisignPath := "../pbo/pkg/bikey/test_data/bin.pbo.dayz.bisign"

	if _, err := os.Stat(privPath); err != nil {
		t.Skipf("fixture not found: %s", privPath)
	}

	priv, err := LoadPrivate(privPath)
	if err != nil {
		t.Fatalf("LoadPrivate fixture: %v", err)
	}

	pub, err := LoadPublic(pubPath)
	if err != nil {
		t.Fatalf("LoadPublic fixture: %v", err)
	}

	if priv.Name != pub.Name {
		t.Errorf("name mismatch: priv=%q pub=%q", priv.Name, pub.Name)
	}

	if priv.Key.PublicKey.N.Cmp(pub.Key.N) != 0 {
		t.Error("modulus mismatch between private and public fixture")
	}

	if _, err := os.Stat(bisignPath); err != nil {
		return
	}

	sig, err := LoadSignature(bisignPath)
	if err != nil {
		t.Fatalf("LoadSignature fixture: %v", err)
	}

	_, err = sig.RecoverHashes()
	if err != nil {
		t.Errorf("RecoverHashes from fixture: %v", err)
	}
}
