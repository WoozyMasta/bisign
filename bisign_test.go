package bisign

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
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
