# mldsa

ML-DSA (FIPS 204) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds post-quantum ML-DSA digital signature support to jwx, enabling ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms for use in JWK, JWS, and JWT operations. JWK representation follows [draft-ietf-cose-dilithium](https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html) using the `AKP` (Algorithm Key Pair) key type.

## Status

**Deprecated once you are on Go 1.27 and jwx v4.4.0.** Go 1.27 ships `crypto/mldsa`, and jwx implements ML-DSA natively from **v4.4.0** on, so this module is only needed below one of those two versions.

Both conditions must hold. jwx v4.3.0 and earlier register no ML-DSA at all, whatever the toolchain, and jwx v4.4.0 built with Go 1.26 does the same, because its ML-DSA files are `//go:build go1.27`. This module remains the way to get ML-DSA in either case.

To migrate when both do hold:

- Drop the `github.com/jwx-go/mldsa/v4` import.
- Replace `filippo.io/mldsa` with `crypto/mldsa`.
- Use `jwa.MLDSA44()`, `jwa.MLDSA65()`, `jwa.MLDSA87()` in place of this package's accessors.

Until you migrate, keeping the import costs nothing. `init()` detects jwx's registration and switches to **interop mode**, where this module implements no ML-DSA of its own and instead converts `filippo.io/mldsa` keys to `crypto/mldsa` so jwx handles them. Both key libraries then work through `jwk`, `jws`, and `jwt`, and a signature made under one verifies under the other. `InteropMode()` reports whether that path was taken.

Two things change in interop mode. `jwsbb` and `dsig` accept `crypto/mldsa` keys only, because they dispatch on the algorithm name and jwx owns those names there. `jwk.Export[any]` returns a `crypto/mldsa` key, so ask for `jwk.Export[*mldsa.PrivateKey]` when you specifically want a `filippo.io/mldsa` one.

Keys held as JWKs need no change either way. This module stays supported for as long as jwx supports Go 1.26.

## Installation

```
go get github.com/jwx-go/mldsa/v4
```

## Usage

Import this package to register ML-DSA algorithms with jwx:

```go
import _ "github.com/jwx-go/mldsa/v4"
```

> **Note:** Registration happens in `init()` and will **panic** if any of
> the ML-DSA algorithms, key types, or importers/exporters fail to register
> (for example, if another module has already claimed the same identifier).
> This is intentional: a half-registered extension would silently produce
> "algorithm not found" errors at signing or verification time, so the
> failure is raised at program start instead.

This registers:

- **Key type**: AKP (Algorithm Key Pair)
- **Signature algorithms**: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **JWK import/export** for ML-DSA public and private keys
- **JWS signing/verification** using ML-DSA

### Sign and verify with raw keys

```go
import (
    "filippo.io/mldsa"
    jwxmldsa "github.com/jwx-go/mldsa/v4"
    "github.com/lestrrat-go/jwx/v4/jws"
)

sk, _ := mldsa.GenerateKey(mldsa.MLDSA65())
signed, _ := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), sk))
verified, _ := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), sk.PublicKey()))
```

### Sign and verify with JWK keys

```go
import (
    "filippo.io/mldsa"
    jwxmldsa "github.com/jwx-go/mldsa/v4"
    "github.com/lestrrat-go/jwx/v4/jwk"
    "github.com/lestrrat-go/jwx/v4/jws"
)

sk, _ := mldsa.GenerateKey(mldsa.MLDSA65())
jwkKey, _ := jwk.Import[jwk.Key](sk)

signed, _ := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), jwkKey))

pubJWK, _ := jwkKey.PublicKey()
verified, _ := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), pubJWK))
```

## Algorithms

| Algorithm | Security Level | Description |
|-----------|---------------|-------------|
| ML-DSA-44 | NIST Level 2 | Smallest signatures, fastest operations |
| ML-DSA-65 | NIST Level 3 | Balanced security and performance |
| ML-DSA-87 | NIST Level 5 | Highest security |

## License

MIT
