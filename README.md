# bisign

[bisign][] is a Go package for working
with `.biprivatekey`, `.bikey`, and `.bisign` files.

It provides key load/save, key generation, signature load/save,
signature creation from `HashSet`, signature verification,
and metadata inspection.

* Reads and writes `.biprivatekey`, `.bikey`, `.bisign` files.
* Parses and marshals payloads from/to in-memory `[]byte`.
* Supports `io.Reader` and `io.Writer` for payloads.
* Recovers signed hashes from `.bisign`.
* Signs and verifies `HashSet` values (three SHA1 digests).
* Imports RSA private keys from PEM/DER sources.
* Generates RSA key pairs with package-supported bit sizes.

> [!NOTE]  
> This package does not compute `hash1/hash2/hash3` from PBO data.
> For working with PBO files, check out the [pbo][] package.

## Installation

Add the module to your project with:

```sh
go get github.com/woozymasta/bisign@latest
```

## Key behavior notes

* Reads and writes signature versions `1`, `2`, and `3`.
* Signs versions `2` and `3`;
  verification checks the block selected by the signature version.
* Generate accepts power-of-two key sizes, starting at `512`.
* Signature blocks in `.bisign` are stored in little-endian byte order.
* Output files are written with `0600` permissions.

<!-- links -->

[pbo]: https://pkg.go.dev/github.com/woozymasta/pbo
[bisign]: https://pkg.go.dev/github.com/woozymasta/bisign
