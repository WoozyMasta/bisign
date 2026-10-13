package bisign

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// fuzzKeyOffsets describes fields in a serialized BI key payload.
type fuzzKeyOffsets struct {
	nameEnd    int // Offset of the name terminator.
	blockSize  int // Offset of the declared payload block size.
	lengthBits int // Offset of the RSA modulus bit length.
	exponent   int // Offset of the RSA public exponent.
	modulus    int // Offset of the RSA modulus bytes.
	prime1     int // Offset of the first private prime.
	prime2     int // Offset of the second private prime.
	dp         int // Offset of the first CRT exponent.
	dq         int // Offset of the second CRT exponent.
	qinv       int // Offset of the CRT coefficient.
	privateExp int // Offset of the private exponent.
	keySize    int // Size of the modulus in bytes.
	primeSize  int // Size of each prime component in bytes.
}

// fuzzSignatureSeed keeps immutable expected data for structure-aware checks.
type fuzzSignatureSeed struct {
	name       string         // Source or synthetic seed identifier.
	signature  *SignatureFile // Valid signature structure for mutation.
	hashes     HashSet        // Independently recorded digest values.
	badPadding [3][]byte      // RSA blocks with deliberately invalid padding.
}

// fuzzFixtureManifest reads canonical fixture paths and reference digests.
type fuzzFixtureManifest struct {
	Keys       map[string]fuzzFixtureKey       `json:"keys"`       // Keys grouped by game.
	Signatures map[string]fuzzFixtureSignature `json:"signatures"` // Signatures grouped by fixture name.
}

// fuzzFixtureKey contains the private-key path used to validate a fixture.
type fuzzFixtureKey struct {
	PrivateKey struct {
		Path string `json:"path"` // Canonical private-key path.
	} `json:"private_key"`
}

// fuzzFixtureSignature contains the independent inputs for one fixture.
type fuzzFixtureSignature struct {
	GameType        string  `json:"game_type"` // Owning game key name.
	Version         Version `json:"version"`   // Signature version in the manifest.
	Path            string  `json:"path"`      // Canonical signature path.
	ReferenceHashes struct {
		Hash1 string `json:"hash1"` // Expected digest for Block1.
		Hash2 string `json:"hash2"` // Expected digest for Block2.
		Hash3 string `json:"hash3"` // Expected digest for Block3.
	} `json:"reference_hashes"`
}

// Fuzz control values select deterministic structural or RSA mutations.
const (
	fuzzVerifyBaseline              byte = iota // Verify an unchanged valid signature.
	fuzzVerifySelectedHash                      // Change the digest selected by the version.
	fuzzVerifySelectedBlock                     // Change the signature block selected by the version.
	fuzzVerifyOtherBlock                        // Change a block not selected by the version.
	fuzzVerifyOtherHash                         // Change a digest not selected by the version.
	fuzzVerifyUnknownVersion                    // Supply an unsupported signature version.
	fuzzVerifyShortBlock                        // Shorten the selected signature block.
	fuzzVerifyLongBlock                         // Lengthen the selected signature block.
	fuzzVerifyBadPadding                        // Use an RSA-valid block with bad PKCS#1 padding.
	fuzzVerifyZeroSignature                     // Set the signature integer to zero.
	fuzzVerifyModulusSignature                  // Set the signature integer to the modulus.
	fuzzVerifyAboveModulusSignature             // Set the signature integer above the modulus.
)

// FuzzParsePublic checks reader parity and canonical roundtrip for BI public keys.
func FuzzParsePublic(f *testing.F) {
	canonical := readFuzzFixture(f, filepath.Join(
		"testdata", "canonical", "dayz", "keys", "BisignDayZReference.bikey",
	))
	addPublicFuzzSeeds(f, canonical)

	minimumKey, err := Generate("fuzz-minimum", MinKeyBits)
	if err != nil {
		f.Fatalf("Generate minimum key: %v", err)
	}
	minimum, err := MarshalPublic(minimumKey.Public())
	if err != nil {
		f.Fatalf("MarshalPublic minimum key: %v", err)
	}
	f.Add(minimum)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, parseErr := ParsePublic(data)
		fromReader, readerErr := LoadPublicFromReader(bytes.NewReader(data))
		if (parseErr == nil) != (readerErr == nil) {
			t.Fatalf("ParsePublic and LoadPublicFromReader disagree: parse=%v reader=%v", parseErr, readerErr)
		}
		if parseErr != nil {
			return
		}
		if !fuzzPublicEqual(parsed, fromReader) {
			t.Fatal("ParsePublic and LoadPublicFromReader returned different keys")
		}

		canonicalBytes, err := MarshalPublic(parsed)
		if err != nil {
			t.Fatalf("MarshalPublic accepted input but rejected parsed key: %v", err)
		}
		roundtrip, err := ParsePublic(canonicalBytes)
		if err != nil {
			t.Fatalf("ParsePublic after MarshalPublic: %v", err)
		}
		if !fuzzPublicEqual(parsed, roundtrip) {
			t.Fatal("public key parameters changed after marshal/parse")
		}

		remarshaled, err := MarshalPublic(roundtrip)
		if err != nil {
			t.Fatalf("MarshalPublic after roundtrip: %v", err)
		}
		if !bytes.Equal(canonicalBytes, remarshaled) {
			t.Fatal("public key serialization did not reach a stable form")
		}
	})
}

// FuzzParsePrivate checks reader parity, RSA invariants, and canonical roundtrip.
func FuzzParsePrivate(f *testing.F) {
	canonical := readFuzzFixture(f, filepath.Join(
		"testdata", "canonical", "dayz", "keys", "BisignDayZReference.biprivatekey",
	))
	addPrivateFuzzSeeds(f, canonical)

	minimumKey, err := Generate("fuzz-minimum", MinKeyBits)
	if err != nil {
		f.Fatalf("Generate minimum key: %v", err)
	}
	minimum, err := MarshalPrivate(minimumKey)
	if err != nil {
		f.Fatalf("MarshalPrivate minimum key: %v", err)
	}
	f.Add(minimum)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, parseErr := ParsePrivate(data)
		fromReader, readerErr := LoadPrivateFromReader(bytes.NewReader(data))
		if (parseErr == nil) != (readerErr == nil) {
			t.Fatalf("ParsePrivate and LoadPrivateFromReader disagree: parse=%v reader=%v", parseErr, readerErr)
		}
		if parseErr != nil {
			return
		}
		if !fuzzPrivateEqual(parsed, fromReader) {
			t.Fatal("ParsePrivate and LoadPrivateFromReader returned different keys")
		}

		canonicalBytes, err := MarshalPrivate(parsed)
		if err != nil {
			t.Fatalf("MarshalPrivate accepted input but rejected parsed key: %v", err)
		}

		roundtrip, err := ParsePrivate(canonicalBytes)
		if err != nil {
			t.Fatalf("ParsePrivate after MarshalPrivate: %v", err)
		}
		if !fuzzPrivateEqual(parsed, roundtrip) {
			t.Fatal("private key parameters changed after marshal/parse")
		}

		remarshaled, err := MarshalPrivate(roundtrip)
		if err != nil {
			t.Fatalf("MarshalPrivate after roundtrip: %v", err)
		}
		if !bytes.Equal(canonicalBytes, remarshaled) {
			t.Fatal("private key serialization did not reach a stable form")
		}
	})
}

// FuzzParseSignature checks parser parity and preserves all serialized blocks.
func FuzzParseSignature(f *testing.F) {
	for _, name := range []string{"dayz-v2", "dayz-v3"} {
		data := readFuzzFixture(f, filepath.Join(
			"testdata", "canonical", "dayz", "signatures", name+ExtBISign,
		))
		signature, err := ParseSignature(data)
		if err != nil {
			f.Fatalf("ParseSignature %s fixture: %v", name, err)
		}

		addSignatureFuzzSeeds(f, data, signature)
		if signature.Version == Version2 {
			syntheticV1 := fuzzMutateU32(data, fuzzSignatureVersionOffset(data), uint32(Version1))
			f.Add(syntheticV1)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, parseErr := ParseSignature(data)
		fromReader, readerErr := LoadSignatureFromReader(bytes.NewReader(data))
		if (parseErr == nil) != (readerErr == nil) {
			t.Fatalf(
				"ParseSignature and LoadSignatureFromReader disagree: parse=%v reader=%v",
				parseErr, readerErr,
			)
		}
		if parseErr != nil {
			return
		}

		if !fuzzSignatureEqual(parsed, fromReader) {
			t.Fatal("ParseSignature and LoadSignatureFromReader returned different signatures")
		}
		if parsed.Version != Version1 && parsed.Version != Version2 && parsed.Version != Version3 {
			t.Fatalf("parser accepted unsupported version %d", parsed.Version)
		}

		keySize := parsed.Public.Key.Size()
		if len(parsed.Block1) != keySize || len(parsed.Block2) != keySize || len(parsed.Block3) != keySize {
			t.Fatal("parser returned signature blocks with inconsistent lengths")
		}

		canonicalBytes, err := MarshalSignature(parsed)
		if err != nil {
			t.Fatalf("MarshalSignature accepted input but rejected parsed signature: %v", err)
		}

		roundtrip, err := ParseSignature(canonicalBytes)
		if err != nil {
			t.Fatalf("ParseSignature after MarshalSignature: %v", err)
		}
		if !fuzzSignatureEqual(parsed, roundtrip) {
			t.Fatal("signature fields changed after marshal/parse")
		}

		remarshaled, err := MarshalSignature(roundtrip)
		if err != nil {
			t.Fatalf("MarshalSignature after roundtrip: %v", err)
		}
		if !bytes.Equal(canonicalBytes, remarshaled) {
			t.Fatal("signature serialization did not reach a stable form")
		}
	})
}

// FuzzVerifyHashes mutates signature inputs while an independent RSA oracle decides validity.
func FuzzVerifyHashes(f *testing.F) {
	seeds := loadVerifyFuzzSeeds(f)
	if len(seeds) == 0 {
		f.Fatal("no signature seeds available")
	}
	for _, seed := range seeds {
		validateVerifyFuzzSeed(f, seed)
	}
	addVerifyFuzzInputs(f, seeds)

	f.Fuzz(func(t *testing.T, data []byte) {
		seedIndex := int(fuzzControlByte(data, 0)) % len(seeds)
		version := Version(fuzzControlByte(data, 1))
		action := fuzzControlByte(data, 2) % 12
		seed := seeds[seedIndex]
		signature := cloneFuzzSignature(seed.signature)
		signature.Version = version
		hashes := seed.hashes

		selected, digest, validVersion := fuzzSelectedPair(signature.Version, &hashes)
		if validVersion {
			blockIndex := int(fuzzControlByte(data, 3))
			blockByte := int(fuzzControlByte(data, 4))
			blockMask := fuzzNonzeroMask(fuzzControlByte(data, 5))
			hashByte := int(fuzzControlByte(data, 6))
			hashMask := fuzzNonzeroMask(fuzzControlByte(data, 7))

			switch action {
			case fuzzVerifySelectedHash:
				fuzzMutateHash(&hashes, selected, hashByte, hashMask)

			case fuzzVerifySelectedBlock:
				block := fuzzBlock(signature, selected)
				block[blockByte%len(block)] ^= blockMask

			case fuzzVerifyOtherBlock:
				other := (selected + 1 + blockIndex%2) % 3
				block := fuzzBlock(signature, other)
				block[blockByte%len(block)] ^= blockMask

			case fuzzVerifyOtherHash:
				other := (selected + 1 + blockIndex%2) % 3
				fuzzMutateHash(&hashes, other, hashByte, hashMask)

			case fuzzVerifyShortBlock:
				block := fuzzBlock(signature, selected)
				fuzzSetBlock(signature, selected, block[:len(block)-1])

			case fuzzVerifyLongBlock:
				block := append(bytes.Clone(fuzzBlock(signature, selected)), blockMask)
				fuzzSetBlock(signature, selected, block)

			case fuzzVerifyBadPadding:
				fuzzSetBlock(signature, selected, bytes.Clone(seed.badPadding[selected]))

			case fuzzVerifyZeroSignature:
				fuzzSetBlock(signature, selected, make([]byte, signature.Public.Key.Size()))

			case fuzzVerifyModulusSignature:
				fuzzSetBlock(signature, selected, fuzzEncodeBIInteger(signature.Public.Key.N, signature.Public.Key.Size()))

			case fuzzVerifyAboveModulusSignature:
				above := new(big.Int).Add(signature.Public.Key.N, big.NewInt(1))
				fuzzSetBlock(signature, selected, fuzzEncodeBIInteger(above, signature.Public.Key.Size()))
			}
		}

		if action == fuzzVerifyUnknownVersion {
			signature.Version = Version(99)
		}

		err := signature.VerifyHashes(hashes)
		if !validSignatureVersion(signature.Version) {
			if !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("VerifyHashes error=%v, want ErrUnsupportedVersion", err)
			}
			return
		}

		if action == fuzzVerifyShortBlock || action == fuzzVerifyLongBlock {
			if !errors.Is(err, ErrSignatureSize) {
				t.Fatalf("VerifyHashes error=%v, want ErrSignatureSize", err)
			}
			return
		}

		selected, digest, _ = fuzzSelectedPair(signature.Version, &hashes)
		valid := independentRSAOracle(signature.Public.Key, fuzzBlock(signature, selected), digest)
		if valid != (err == nil) {
			t.Fatalf(
				"VerifyHashes acceptance=%t differs from independent RSA oracle=%t (version=%d action=%d)",
				err == nil, valid, signature.Version, action,
			)
		}
	})
}

// TestVerifyFuzzOracleFindsSelectedBlockCorruption demonstrates an invariant missed by parse-only fuzzing.
func TestVerifyFuzzOracleFindsSelectedBlockCorruption(t *testing.T) {
	seed := loadOriginalVerifyFuzzSeed(t, "dayz-v3")
	signature := cloneFuzzSignature(seed.signature)
	signature.Block3[0] ^= 0xff

	serialized, err := MarshalSignature(signature)
	if err != nil {
		t.Fatalf("MarshalSignature structurally valid corruption: %v", err)
	}

	parsed, err := ParseSignature(serialized)
	if err != nil {
		t.Fatalf("ParseSignature structurally valid corruption: %v", err)
	}

	if independentRSAOracle(parsed.Public.Key, parsed.Block3, seed.hashes.Hash3[:]) {
		t.Fatal("oracle accepted deliberately corrupted selected signature block")
	}
	if err := parsed.VerifyHashes(seed.hashes); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("VerifyHashes error=%v, want ErrVerifyFailed", err)
	}
}

// TestRecoverHashesRejectsEachInvalidBlock verifies the all-block recovery contract.
func TestRecoverHashesRejectsEachInvalidBlock(t *testing.T) {
	priv, err := Generate("recover-fuzz-check", MinKeyBits)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	hashes := fuzzSyntheticHashes()
	signature, err := signFuzzHashSetRaw(priv.Key, hashes, Version3)
	if err != nil {
		t.Fatalf("sign synthetic hashes: %v", err)
	}

	badPadding := fuzzBadPaddingBlocks(priv.Key, hashes)
	if _, err := signature.RecoverHashes(); err != nil {
		t.Fatalf("RecoverHashes valid seed: %v", err)
	}

	for blockIndex := 0; blockIndex < 3; blockIndex++ {
		candidate := cloneFuzzSignature(signature)
		fuzzSetBlock(candidate, blockIndex, bytes.Clone(badPadding[blockIndex]))
		if recovered, err := candidate.RecoverHashes(); err == nil || recovered != (HashSet{}) {
			t.Errorf("RecoverHashes block %d returned partial result=%+v, err=%v", blockIndex+1, recovered, err)
		}
	}
}

// addPublicFuzzSeeds adds canonical, minimum-size, and structural boundary samples.
func addPublicFuzzSeeds(f *testing.F, canonical []byte) {
	f.Add(bytes.Clone(canonical))
	f.Add([]byte{})
	if offsets, ok := fuzzKeyFieldOffsets(canonical); ok {
		for _, end := range []int{
			1,
			offsets.nameEnd,
			offsets.blockSize + 2,
			offsets.modulus + 1,
			len(canonical) - 1,
		} {
			if end > 0 && end < len(canonical) {
				f.Add(bytes.Clone(canonical[:end]))
			}
		}

		badBlockSize := fuzzMutateU32(canonical, offsets.blockSize, ^uint32(0))
		f.Add(badBlockSize)
		for _, bits := range []uint32{0, uint32(MinKeyBits - 8), uint32(MaxKeyBits + 1), 768} {
			f.Add(fuzzMutateU32(canonical, offsets.lengthBits, bits))
		}
		for _, exponent := range []uint32{0, 1, ^uint32(0)} {
			f.Add(fuzzMutateU32(canonical, offsets.exponent, exponent))
		}

		badModulus := bytes.Clone(canonical)
		clear(badModulus[offsets.modulus : offsets.modulus+offsets.keySize])

		f.Add(badModulus)
		badTerminator := bytes.Clone(canonical)
		badTerminator[offsets.nameEnd] = 'x'
		f.Add(badTerminator)
	}

	trailing := append(bytes.Clone(canonical), 0)
	f.Add(trailing)
	f.Add(bytes.Repeat([]byte{0}, MaxPublicKeyFileBytes+1))
}

// addPrivateFuzzSeeds adds canonical, minimum-size, and component mutation samples.
func addPrivateFuzzSeeds(f *testing.F, canonical []byte) {
	f.Add(bytes.Clone(canonical))
	f.Add([]byte{})
	offsets, ok := fuzzKeyFieldOffsets(canonical)
	if !ok {
		return
	}

	for _, end := range []int{
		1,
		offsets.nameEnd,
		offsets.blockSize + 2,
		offsets.modulus + 1,
		offsets.prime1 + 1,
		offsets.privateExp + 1,
		len(canonical) - 1,
	} {
		if end > 0 && end < len(canonical) {
			f.Add(bytes.Clone(canonical[:end]))
		}
	}

	badBlockSize := fuzzMutateU32(canonical, offsets.blockSize, ^uint32(0))
	f.Add(badBlockSize)
	for _, bits := range []uint32{0, uint32(MinKeyBits - 8), uint32(MaxKeyBits + 1), 768} {
		f.Add(fuzzMutateU32(canonical, offsets.lengthBits, bits))
	}

	for _, componentOffset := range []int{offsets.modulus, offsets.prime1, offsets.prime2, offsets.privateExp} {
		badComponent := bytes.Clone(canonical)
		componentSize := offsets.keySize
		if componentOffset == offsets.prime1 || componentOffset == offsets.prime2 {
			componentSize = offsets.primeSize
		}
		clear(badComponent[componentOffset : componentOffset+componentSize])
		f.Add(badComponent)
	}

	for _, componentOffset := range []int{offsets.dp, offsets.dq, offsets.qinv} {
		badCRT := bytes.Clone(canonical)
		clear(badCRT[componentOffset : componentOffset+offsets.primeSize])
		f.Add(badCRT)
	}

	badTerminator := bytes.Clone(canonical)
	badTerminator[offsets.nameEnd] = 'x'
	f.Add(badTerminator)
	trailing := append(bytes.Clone(canonical), 0)
	f.Add(trailing)
	f.Add(bytes.Repeat([]byte{0}, MaxPrivateKeyFileBytes+1))
}

// addSignatureFuzzSeeds adds version, framing, and cryptographic-block mutations.
func addSignatureFuzzSeeds(f *testing.F, canonical []byte, signature *SignatureFile) {
	f.Add(bytes.Clone(canonical))
	f.Add([]byte{})
	offsets, ok := fuzzSignatureFieldOffsets(canonical)
	if !ok {
		f.Fatalf("cannot locate signature fields in canonical seed")
	}

	for _, end := range []int{
		1,
		offsets.block1Length + 2,
		offsets.block1 + 1,
		offsets.version + 2,
		offsets.block2 + 1,
		offsets.block3 + 1,
		len(canonical) - 1,
	} {
		if end > 0 && end < len(canonical) {
			f.Add(bytes.Clone(canonical[:end]))
		}
	}

	for _, version := range []uint32{0, 1, 2, 3, 4, ^uint32(0)} {
		f.Add(fuzzMutateU32(canonical, offsets.version, version))
	}
	for _, lengthOffset := range []int{offsets.block1Length, offsets.block2Length, offsets.block3Length} {
		f.Add(fuzzMutateU32(canonical, lengthOffset, 0))
		f.Add(fuzzMutateU32(canonical, lengthOffset, uint32(signature.Public.Key.Size()-1)))
	}

	badBlock := bytes.Clone(canonical)
	badBlock[offsets.block3] ^= 0xff
	f.Add(badBlock)
	badExponent := fuzzMutateU32(canonical, offsets.public.exponent, 1)
	f.Add(badExponent)
	badModulus := bytes.Clone(canonical)
	clear(badModulus[offsets.public.modulus : offsets.public.modulus+offsets.public.keySize])

	f.Add(badModulus)
	f.Add(append(bytes.Clone(canonical), 0))
	f.Add(bytes.Repeat([]byte{0}, MaxSignatureFileBytes+1))
}

// addVerifyFuzzInputs adds a compact version and mutation matrix for both key sizes.
func addVerifyFuzzInputs(f *testing.F, seeds []fuzzSignatureSeed) {
	for seedIndex, seed := range seeds {
		for _, version := range []Version{Version1, Version2, Version3} {
			f.Add(encodeVerifyControl(seedIndex, version, fuzzVerifyBaseline))
		}
		_ = seed
	}

	for _, version := range []Version{Version1, Version2, Version3} {
		seedIndex := verifySeedIndexForVersion(seeds, version, false)
		for action := byte(fuzzVerifySelectedHash); action <= fuzzVerifyAboveModulusSignature; action++ {
			f.Add(encodeVerifyControl(seedIndex, version, action))
		}
		originalIndex := verifySeedIndexForVersion(seeds, version, true)
		f.Add(encodeVerifyControl(originalIndex, version, fuzzVerifyOtherBlock))
		f.Add(encodeVerifyControl(originalIndex, version, fuzzVerifyOtherHash))
	}

	f.Add(encodeVerifyControl(0, Version(0), fuzzVerifyBaseline))
	f.Add(encodeVerifyControl(0, Version3, fuzzVerifyUnknownVersion))
}

// loadVerifyFuzzSeeds loads original test signatures and creates synthetic small-key cases.
func loadVerifyFuzzSeeds(f *testing.F) []fuzzSignatureSeed {
	manifestData := readFuzzFixture(f, filepath.Join("testdata", "canonical", "manifest.json"))
	var manifest fuzzFixtureManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		f.Fatalf("decode canonical manifest: %v", err)
	}

	privateKeys := make(map[string]*rsa.PrivateKey, len(manifest.Keys))
	for game, keyInfo := range manifest.Keys {
		private, err := LoadPrivate(
			filepath.Join("testdata", "canonical", filepath.FromSlash(keyInfo.PrivateKey.Path)),
		)
		if err != nil {
			f.Fatalf("LoadPrivate %s fixture: %v", game, err)
		}

		privateKeys[game] = private.Key
	}

	seeds := make([]fuzzSignatureSeed, 0, 8)
	for _, name := range []string{"dayz-v2", "dayz-v3", "arma-v2", "arma-v3"} {
		fixture, ok := manifest.Signatures[name]
		if !ok {
			f.Fatalf("canonical signature fixture %q missing from manifest", name)
		}

		signature, err := LoadSignature(
			filepath.Join("testdata", "canonical", filepath.FromSlash(fixture.Path)),
		)
		if err != nil {
			f.Fatalf("LoadSignature %s fixture: %v", name, err)
		}

		private := privateKeys[fixture.GameType]
		if private == nil || private.N.Cmp(signature.Public.Key.N) != 0 || private.E != signature.Public.Key.E {
			f.Fatalf("%s fixture key does not match its embedded public key", name)
		}

		seed := fuzzSignatureSeed{
			name:      name,
			signature: signature,
			hashes: fuzzManifestHashes(
				f,
				fixture.ReferenceHashes.Hash1,
				fixture.ReferenceHashes.Hash2,
				fixture.ReferenceHashes.Hash3,
			),
		}

		seed.badPadding = fuzzBadPaddingBlocks(private, seed.hashes)
		seeds = append(seeds, seed)
	}

	dayzV2 := cloneFuzzSignature(seeds[0].signature)
	dayzV2.Version = Version1
	seeds = append(seeds, fuzzSignatureSeed{
		name:       "synthetic-v1-from-dayz-v2",
		signature:  dayzV2,
		hashes:     seeds[0].hashes,
		badPadding: seeds[0].badPadding,
	})

	smallKey, err := Generate("small-fuzz-key", 512)
	if err != nil {
		f.Fatalf("Generate small fuzz key: %v", err)
	}

	smallHashes := fuzzSyntheticHashes()
	smallSignature, err := signFuzzHashSetRaw(smallKey.Key, smallHashes, Version3)
	if err != nil {
		f.Fatalf("sign small-key hashes: %v", err)
	}

	smallBadPadding := fuzzBadPaddingBlocks(smallKey.Key, smallHashes)
	for _, version := range []Version{Version1, Version2, Version3} {
		signature := cloneFuzzSignature(smallSignature)
		signature.Version = version
		seeds = append(seeds, fuzzSignatureSeed{
			name:       fmt.Sprintf("synthetic-small-v%d", version),
			signature:  signature,
			hashes:     smallHashes,
			badPadding: smallBadPadding,
		})
	}

	return seeds
}

// validateVerifyFuzzSeed fails setup if a seed does not pass independent checks.
func validateVerifyFuzzSeed(f *testing.F, seed fuzzSignatureSeed) {
	if seed.signature == nil {
		f.Fatalf("signature seed %q is incomplete", seed.name)
	}

	if !validSignatureVersion(seed.signature.Version) {
		f.Fatalf("signature seed %q has unsupported version %d", seed.name, seed.signature.Version)
	}

	for index := 0; index < 3; index++ {
		if !independentRSAOracle(
			seed.signature.Public.Key,
			fuzzBlock(seed.signature, index),
			fuzzHashAt(&seed.hashes, index),
		) {
			f.Fatalf("signature seed %q block %d failed independent RSA validation", seed.name, index+1)
		}
	}

	if err := seed.signature.VerifyHashes(seed.hashes); err != nil {
		f.Fatalf("signature seed %q failed VerifyHashes: %v", seed.name, err)
	}
}

// loadOriginalVerifyFuzzSeed loads one original fixture and its independent manifest hashes.
func loadOriginalVerifyFuzzSeed(t testing.TB, name string) fuzzSignatureSeed {
	t.Helper()
	manifestData := readFuzzFixture(t, filepath.Join("testdata", "canonical", "manifest.json"))
	var manifest fuzzFixtureManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode canonical manifest: %v", err)
	}

	fixture, ok := manifest.Signatures[name]
	if !ok {
		t.Fatalf("canonical signature fixture %q missing from manifest", name)
	}

	signature, err := LoadSignature(
		filepath.Join("testdata", "canonical", filepath.FromSlash(fixture.Path)),
	)
	if err != nil {
		t.Fatalf("LoadSignature %s fixture: %v", name, err)
	}

	keyInfo := manifest.Keys[fixture.GameType]
	private, err := LoadPrivate(
		filepath.Join("testdata", "canonical", filepath.FromSlash(keyInfo.PrivateKey.Path)),
	)
	if err != nil {
		t.Fatalf("LoadPrivate %s fixture: %v", fixture.GameType, err)
	}

	seed := fuzzSignatureSeed{
		name:      name,
		signature: signature,
		hashes: fuzzManifestHashes(
			t,
			fixture.ReferenceHashes.Hash1,
			fixture.ReferenceHashes.Hash2,
			fixture.ReferenceHashes.Hash3,
		),
	}
	seed.badPadding = fuzzBadPaddingBlocks(private.Key, seed.hashes)

	return seed
}

// fuzzManifestHashes decodes independent digest vectors from the canonical manifest.
func fuzzManifestHashes(t testing.TB, hash1, hash2, hash3 string) HashSet {
	t.Helper()
	return HashSet{
		Hash1: fuzzDecodeDigest(t, hash1),
		Hash2: fuzzDecodeDigest(t, hash2),
		Hash3: fuzzDecodeDigest(t, hash3),
	}
}

// fuzzDecodeDigest decodes one fixed-width SHA-1 digest.
func fuzzDecodeDigest(t testing.TB, value string) [20]byte {
	t.Helper()
	var digest [20]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		t.Fatalf("invalid SHA-1 digest %q: %v", value, err)
	}

	copy(digest[:], decoded)
	return digest
}

// signFuzzHashSetRaw creates test signatures without calling SignHashes.
func signFuzzHashSetRaw(key *rsa.PrivateKey, hashes HashSet, version Version) (*SignatureFile, error) {
	signature := &SignatureFile{
		Public:  &PublicKeyFile{Name: "synthetic-fuzz", Key: &key.PublicKey},
		Version: version,
	}

	for index := 0; index < 3; index++ {
		encoded, err := independentPKCS1v15SHA1(key.Size(), fuzzHashAt(&hashes, index))
		if err != nil {
			return nil, fmt.Errorf("encode digest for block %d: %w", index+1, err)
		}

		message := new(big.Int).SetBytes(encoded)
		s := new(big.Int).Exp(message, key.D, key.N)
		fuzzSetBlock(signature, index, fuzzEncodeBIInteger(s, key.Size()))
	}

	return signature, nil
}

// fuzzBadPaddingBlocks builds RSA-valid signatures over noncanonical encoded messages.
func fuzzBadPaddingBlocks(key *rsa.PrivateKey, hashes HashSet) [3][]byte {
	var blocks [3][]byte
	for index := range blocks {
		encoded := independentPKCS1v15SHA1WithPadding(key.Size(), fuzzHashAt(&hashes, index), 7)
		message := new(big.Int).SetBytes(encoded)
		s := new(big.Int).Exp(message, key.D, key.N)
		blocks[index] = fuzzEncodeBIInteger(s, key.Size())
	}

	return blocks
}

// independentRSAOracle checks the complete encoded message without using bisign recovery helpers.
func independentRSAOracle(pub *rsa.PublicKey, block, digest []byte) bool {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E <= 1 || len(digest) != 20 {
		return false
	}
	if pub.N.BitLen() < MinKeyBits || pub.N.BitLen() > MaxKeyBits || uint64(pub.E) > uint64(^uint32(0)) {
		return false
	}
	if len(block) != pub.Size() {
		return false
	}

	if pub.Size()*8 >= 1024 {
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, fuzzReverseCopy(block)) == nil
	}

	signature := new(big.Int).SetBytes(fuzzReverseCopy(block))
	if signature.Sign() <= 0 || signature.Cmp(pub.N) >= 0 {
		return false
	}

	encodedInt := new(big.Int).Exp(signature, big.NewInt(int64(pub.E)), pub.N)
	encoded := make([]byte, pub.Size())
	encodedInt.FillBytes(encoded)
	expected, err := independentPKCS1v15SHA1(pub.Size(), digest)
	if err != nil {
		return false
	}

	return bytes.Equal(encoded, expected)
}

// independentPKCS1v15SHA1 creates the expected full EMSA-PKCS1-v1_5 SHA-1 block.
func independentPKCS1v15SHA1(keySize int, digest []byte) ([]byte, error) {
	if len(digest) != 20 {
		return nil, fmt.Errorf("digest length=%d, want 20", len(digest))
	}
	return independentPKCS1v15SHA1WithPadding(keySize, digest, -1), nil
}

// independentPKCS1v15SHA1WithPadding builds canonical padding or a requested test length.
func independentPKCS1v15SHA1WithPadding(keySize int, digest []byte, paddingLength int) []byte {
	prefix := [...]byte{
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
	}

	message := make([]byte, keySize)
	message[0] = 0
	message[1] = 1

	if paddingLength < 0 {
		paddingLength = keySize - len(prefix) - len(digest) - 3
	}

	for index := 0; index < paddingLength; index++ {
		message[2+index] = 0xff
	}

	separator := 2 + paddingLength
	if separator >= len(message) {
		return nil
	}

	message[separator] = 0
	copy(message[separator+1:], prefix[:])
	copy(message[separator+1+len(prefix):], digest)

	return message
}

// readFuzzFixture loads an immutable test corpus file before fuzz callbacks run.
func readFuzzFixture(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}

	return data
}

// fuzzKeyFieldOffsets locates key fields in a valid public or private BI key payload.
func fuzzKeyFieldOffsets(data []byte) (fuzzKeyOffsets, bool) {
	var offsets fuzzKeyOffsets
	nameEnd := bytes.IndexByte(data, 0)
	if nameEnd < 0 {
		return offsets, false
	}

	offsets.nameEnd = nameEnd
	offsets.blockSize = nameEnd + 1
	offsets.lengthBits = offsets.blockSize + 4 + 12
	offsets.exponent = offsets.lengthBits + 4
	offsets.modulus = offsets.exponent + 4
	if offsets.modulus+4 > len(data) {
		return fuzzKeyOffsets{}, false
	}

	bits := binary.LittleEndian.Uint32(data[offsets.lengthBits : offsets.lengthBits+4])
	if bits == 0 || bits%8 != 0 {
		return fuzzKeyOffsets{}, false
	}

	offsets.keySize = int(bits / 8)
	offsets.primeSize = int(bits / 16)
	offsets.prime1 = offsets.modulus + offsets.keySize
	offsets.prime2 = offsets.prime1 + offsets.primeSize
	offsets.dp = offsets.prime2 + offsets.primeSize
	offsets.dq = offsets.dp + offsets.primeSize
	offsets.qinv = offsets.dq + offsets.primeSize
	offsets.privateExp = offsets.qinv + offsets.primeSize

	return offsets, true
}

// fuzzSignatureOffsets describes the three length-prefixed blocks in a signature payload.
type fuzzSignatureOffsets struct {
	public       fuzzKeyOffsets // Embedded public-key field offsets.
	block1Length int            // Offset of Block1's encoded length.
	block1       int            // Offset of Block1 bytes.
	version      int            // Offset of the signature version.
	block2Length int            // Offset of Block2's encoded length.
	block2       int            // Offset of Block2 bytes.
	block3Length int            // Offset of Block3's encoded length.
	block3       int            // Offset of Block3 bytes.
	blockSize    int            // Expected size of each RSA block.
}

// fuzzSignatureFieldOffsets locates signature fields using the embedded BI public key header.
func fuzzSignatureFieldOffsets(data []byte) (fuzzSignatureOffsets, bool) {
	var offsets fuzzSignatureOffsets
	public, ok := fuzzKeyFieldOffsets(data)
	if !ok {
		return offsets, false
	}

	publicEnd := public.modulus + public.keySize
	if publicEnd+4+public.keySize+4 > len(data) {
		return offsets, false
	}

	offsets.public = public
	offsets.block1Length = publicEnd
	offsets.block1 = offsets.block1Length + 4
	offsets.version = offsets.block1 + public.keySize
	offsets.block2Length = offsets.version + 4
	offsets.block2 = offsets.block2Length + 4
	offsets.block3Length = offsets.block2 + public.keySize
	offsets.block3 = offsets.block3Length + 4
	offsets.blockSize = public.keySize

	return offsets, offsets.block3+public.keySize <= len(data)
}

// fuzzMutateU32 clones data and replaces one little-endian field.
func fuzzMutateU32(data []byte, offset int, value uint32) []byte {
	mutated := bytes.Clone(data)
	if offset >= 0 && offset+4 <= len(mutated) {
		binary.LittleEndian.PutUint32(mutated[offset:offset+4], value)
	}

	return mutated
}

// fuzzPublicEqual compares the public identity fields that BI serialization preserves.
func fuzzPublicEqual(left, right *PublicKeyFile) bool {
	if left == nil || right == nil || left.Key == nil || right.Key == nil {
		return left == nil && right == nil
	}

	return left.Name == right.Name && left.Key.E == right.Key.E && left.Key.N.Cmp(right.Key.N) == 0
}

// fuzzPrivateEqual compares RSA fields that BI private-key serialization preserves.
func fuzzPrivateEqual(left, right *PrivateKeyFile) bool {
	if !fuzzPublicEqual(privatePublic(left), privatePublic(right)) {
		return false
	}
	if left == nil || right == nil || left.Key == nil || right.Key == nil || left.Name != right.Name {
		return false
	}
	if left.Key.D.Cmp(right.Key.D) != 0 || len(left.Key.Primes) < 2 || len(right.Key.Primes) < 2 {
		return false
	}

	return left.Key.Primes[0].Cmp(right.Key.Primes[0]) == 0 && left.Key.Primes[1].Cmp(right.Key.Primes[1]) == 0
}

// privatePublic exposes public fields for common identity comparison.
func privatePublic(key *PrivateKeyFile) *PublicKeyFile {
	if key == nil || key.Key == nil {
		return nil
	}

	return &PublicKeyFile{Name: key.Name, Key: &key.Key.PublicKey}
}

// fuzzSignatureEqual compares all serialized signature fields.
func fuzzSignatureEqual(left, right *SignatureFile) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Version == right.Version &&
		fuzzPublicEqual(left.Public, right.Public) &&
		bytes.Equal(left.Block1, right.Block1) &&
		bytes.Equal(left.Block2, right.Block2) &&
		bytes.Equal(left.Block3, right.Block3)
}

// fuzzSignatureVersionOffset returns the version field offset for a valid signature payload.
func fuzzSignatureVersionOffset(data []byte) int {
	offsets, ok := fuzzSignatureFieldOffsets(data)
	if !ok {
		return -1
	}

	return offsets.version
}

// validSignatureVersion reports whether a version selects one of the three BI signature blocks.
func validSignatureVersion(version Version) bool {
	return version == Version1 || version == Version2 || version == Version3
}

// cloneFuzzSignature returns an independent copy of key and block data.
func cloneFuzzSignature(source *SignatureFile) *SignatureFile {
	copyOf := *source
	public := *source.Public
	public.Key = &rsa.PublicKey{N: new(big.Int).Set(source.Public.Key.N), E: source.Public.Key.E}
	copyOf.Public = &public
	copyOf.Block1 = bytes.Clone(source.Block1)
	copyOf.Block2 = bytes.Clone(source.Block2)
	copyOf.Block3 = bytes.Clone(source.Block3)

	return &copyOf
}

// fuzzSelectedPair returns the block and digest selected by a signature version.
func fuzzSelectedPair(version Version, hashes *HashSet) (int, []byte, bool) {
	switch version {
	case Version1:
		return 0, hashes.Hash1[:], true
	case Version2:
		return 1, hashes.Hash2[:], true
	case Version3:
		return 2, hashes.Hash3[:], true
	default:
		return 0, nil, false
	}
}

// fuzzBlock returns one mutable signature block by its fixed field index.
func fuzzBlock(signature *SignatureFile, index int) []byte {
	switch index {
	case 0:
		return signature.Block1
	case 1:
		return signature.Block2
	default:
		return signature.Block3
	}
}

// fuzzSetBlock replaces one signature block by its fixed field index.
func fuzzSetBlock(signature *SignatureFile, index int, block []byte) {
	switch index {
	case 0:
		signature.Block1 = block
	case 1:
		signature.Block2 = block
	default:
		signature.Block3 = block
	}
}

// fuzzHashAt returns one digest by its fixed field index.
func fuzzHashAt(hashes *HashSet, index int) []byte {
	switch index {
	case 0:
		return hashes.Hash1[:]
	case 1:
		return hashes.Hash2[:]
	default:
		return hashes.Hash3[:]
	}
}

// fuzzMutateHash flips a nonzero mask at one digest byte.
func fuzzMutateHash(hashes *HashSet, index, byteIndex int, mask byte) {
	digest := fuzzHashAt(hashes, index)
	digest[byteIndex%len(digest)] ^= mask
}

// fuzzControlByte reads one mutation control byte, defaulting missing bytes to zero.
func fuzzControlByte(data []byte, index int) byte {
	if index >= len(data) {
		return 0
	}

	return data[index]
}

// fuzzNonzeroMask prevents a selected-byte mutation from becoming a no-op.
func fuzzNonzeroMask(mask byte) byte {
	if mask == 0 {
		return 1
	}

	return mask
}

// fuzzEncodeBIInteger serializes a fixed-width integer in BI little-endian order.
func fuzzEncodeBIInteger(value *big.Int, size int) []byte {
	encoded := make([]byte, size)
	value.FillBytes(encoded)
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}

	return encoded
}

// fuzzReverseCopy reverses a byte slice without changing the caller's block.
func fuzzReverseCopy(data []byte) []byte {
	copyOf := bytes.Clone(data)
	for left, right := 0, len(copyOf)-1; left < right; left, right = left+1, right-1 {
		copyOf[left], copyOf[right] = copyOf[right], copyOf[left]
	}

	return copyOf
}

// fuzzSyntheticHashes supplies independent fixed digest values for generated test keys.
func fuzzSyntheticHashes() HashSet {
	var hashes HashSet
	for index := range hashes.Hash1 {
		hashes.Hash1[index] = byte(index + 3)
		hashes.Hash2[index] = byte(index + 43)
		hashes.Hash3[index] = byte(index + 83)
	}

	return hashes
}

// encodeVerifyControl encodes a fuzz seed and one controlled verification action.
func encodeVerifyControl(seed int, version Version, action byte) []byte {
	return []byte{byte(seed), byte(version), action, 1, 0x5a, 7, 0, 0xa5}
}

// verifySeedIndexForVersion chooses a prepared seed with requested key size and version.
func verifySeedIndexForVersion(seeds []fuzzSignatureSeed, version Version, original bool) int {
	for index, seed := range seeds {
		if seed.signature.Version != version {
			continue
		}

		if original && !stringsHasPrefix(seed.name, "synthetic-") {
			return index
		}
		if !original && stringsHasPrefix(seed.name, "synthetic-small-") {
			return index
		}
	}

	return 0
}

// stringsHasPrefix avoids a string package dependency in the fuzz harness.
func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
