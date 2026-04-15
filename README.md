# mldsa

ML-DSA (FIPS 204) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds post-quantum ML-DSA digital signature support to jwx, enabling ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms for use in JWK, JWS, and JWT operations. JWK representation follows [draft-ietf-cose-dilithium](https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html) using the `AKP` (Algorithm Key Pair) key type.

## Status

**Work in progress.** This module exists as a temporary bridge using [filippo.io/mldsa](https://filippo.io/mldsa) until Go includes `crypto/mldsa` in the standard library ([golang/go#77626](https://github.com/golang/go/issues/77626)). Once that lands, ML-DSA support will likely move directly into jwx and this module will be deprecated.

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
