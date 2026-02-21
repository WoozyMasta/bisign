package bisign

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := Generate("bench", 1024)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadPrivate(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.biprivatekey")
	if err := WritePrivate(path, priv); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadPrivate(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWritePrivate(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := serializePrivate(priv)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWritePrivateFile(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.biprivatekey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := path + ".tmp"
		if err := WritePrivate(p, priv); err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(p)
	}
}

func BenchmarkLoadPublic(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.bikey")
	if err := WritePublic(path, priv.Public()); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadPublic(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignHashes(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	var hs HashSet
	for i := range hs.Hash1 {
		hs.Hash1[i] = byte(i)
		hs.Hash2[i] = byte(i)
		hs.Hash3[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.SignHashes(3, hs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadSignature(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	var hs HashSet
	sig, _ := priv.SignHashes(3, hs)
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.bisign")
	if err := WriteSignature(path, sig); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadSignature(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecoverHashes(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	var hs HashSet
	sig, _ := priv.SignHashes(3, hs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sig.RecoverHashes()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHashes(b *testing.B) {
	priv, _ := Generate("bench", 1024)
	var hs HashSet
	sig, _ := priv.SignHashes(3, hs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sig.VerifyHashes(hs); err != nil {
			b.Fatal(err)
		}
	}
}
