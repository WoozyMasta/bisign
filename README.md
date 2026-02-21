# bisign

`bisign` is a Go package for working with `.biprivatekey`, `.bikey`,
and `.bisign` files.

It provides key load/save, key generation, signature load/save,
signature creation from `HashSet`, signature verification,
and metadata inspection.

* Reads and writes `.biprivatekey`, `.bikey`, `.bisign` files.
* Parses and marshals payloads from/to in-memory `[]byte`.
* Supports `io.Reader` and `io.Writer` for payloads.
* Recovers signed hashes from `.bisign`.
* Signs and verifies `HashSet` values (three SHA1 digests).
* Imports RSA private keys from common OpenSSH/PEM/DER sources.
* Generates RSA key pairs with package-supported bit sizes.

> [!NOTE]  
> This package does not compute `hash1/hash2/hash3` from PBO data.

## Usage examples

### Generate key pair

```go
priv, err := bisign.Generate("mykey", 1024)
if err != nil {
    return err
}

if err := bisign.WritePrivate("mykey.biprivatekey", priv); err != nil {
    return err
}

if err := bisign.WritePublic("mykey.bikey", priv.Public()); err != nil {
    return err
}
```

### Sign a prepared hash set

```go
var hs bisign.HashSet
// fill hs.Hash1, hs.Hash2, hs.Hash3 with 20-byte SHA1 digests

sig, err := priv.SignHashes(bisign.Version3, hs)
if err != nil {
    return err
}

if err := bisign.WriteSignature("file.pbo.mykey.bisign", sig); err != nil {
    return err
}
```

### Load and verify signature

```go
sig, err := bisign.LoadSignature("file.pbo.mykey.bisign")
if err != nil {
    return err
}

if err := sig.VerifyHashes(hs); err != nil {
    return err
}
```

### Inspect file metadata

```go
info, err := bisign.Inspect("mykey.bikey")
if err != nil {
    return err
}

_ = info
```

## Key behavior notes

* Supported signature versions: `2` and `3`.
* Generate accepts power-of-two key sizes, starting at `512`.
* Signature blocks in `.bisign` are stored in little-endian byte order.
* Output files are written with `0600` permissions.
