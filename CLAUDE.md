# ML-DSA Extension for JWX

## Overview

This module (`github.com/jwx-go/mldsa`) provides ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) support for `github.com/lestrrat-go/jwx/v4`.

ML-DSA is a post-quantum digital signature scheme. This module bridges the `filippo.io/mldsa` implementation into jwx's algorithm registration system, enabling ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.

## Architecture

This module follows the same external extension pattern as `ext/es256k` in jwx:

- Registers ML-DSA signature algorithms with `jwa`
- Registers ML-DSA key type with `jwa`
- Provides `jwk.Key` import/export for ML-DSA raw keys
- Implements `jws.Signer` and `jws.Verifier` for ML-DSA algorithms
- Maps ML-DSA algorithms to `dsig` algorithm identifiers

### Integration Points with JWX

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterSignatureAlgorithm()` | Register ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| `jwa` | `RegisterKeyType()` | Register ML-DSA key type |
| `jwk` | `RegisterKeyParser()` | Parse ML-DSA JWK JSON |
| `jwk` | `RegisterKeyImporter()` | Convert raw ML-DSA keys to `jwk.Key` |
| `jwk` | `RegisterKeyExporter()` | Convert `jwk.Key` to raw ML-DSA keys |
| `jws` | `RegisterSigner()` | ML-DSA signing |
| `jws` | `RegisterVerifier()` | ML-DSA verification |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate algorithms with key type |

### Dependency on filippo.io/mldsa

This module currently depends on `filippo.io/mldsa` for the underlying ML-DSA implementation. Once Go ships `crypto/mldsa` (tracking: https://github.com/golang/go/issues/77626), this module will migrate to the standard library implementation and this separate module may become unnecessary — the support could move directly into jwx.

## Algorithms

| Algorithm | FIPS 204 Parameter Set | Security Level |
|-----------|----------------------|----------------|
| ML-DSA-44 | ML-DSA-44 | NIST Level 2 (roughly equivalent to AES-128) |
| ML-DSA-65 | ML-DSA-65 | NIST Level 3 (roughly equivalent to AES-192) |
| ML-DSA-87 | ML-DSA-87 | NIST Level 5 (roughly equivalent to AES-256) |

## Build / Test

```
go test ./...
```

## Module Path

```
github.com/jwx-go/mldsa
```
