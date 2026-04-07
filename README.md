# mldsa

ML-DSA (FIPS 204) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds post-quantum ML-DSA digital signature support to jwx, enabling ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms for use in JWK, JWS, and JWT operations.

## Status

**Work in progress.** This module exists as a temporary bridge using [filippo.io/mldsa](https://filippo.io/mldsa) until Go includes `crypto/mldsa` in the standard library ([golang/go#77626](https://github.com/golang/go/issues/77626)). Once that lands, ML-DSA support will likely move directly into jwx and this module will be deprecated.

## Installation

```
go get github.com/jwx-go/mldsa
```

## Usage

Import this package to register ML-DSA algorithms with jwx:

```go
import _ "github.com/jwx-go/mldsa"
```

This registers:

- **Key type**: ML-DSA
- **Signature algorithms**: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **JWK import/export** for ML-DSA public and private keys
- **JWS signing/verification** using ML-DSA

## Algorithms

| Algorithm | Security Level | Description |
|-----------|---------------|-------------|
| ML-DSA-44 | NIST Level 2 | Smallest signatures, fastest operations |
| ML-DSA-65 | NIST Level 3 | Balanced security and performance |
| ML-DSA-87 | NIST Level 5 | Highest security |

## License

MIT
