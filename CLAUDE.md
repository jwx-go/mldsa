# ML-DSA Extension for JWX

## Overview

This module (`github.com/jwx-go/mldsa/v4`) provides ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) support for `github.com/lestrrat-go/jwx`.

ML-DSA is a post-quantum digital signature scheme. This module bridges the `filippo.io/mldsa` implementation into jwx's algorithm registration system, enabling ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.

## Architecture

This module implements a custom `jwk.Key` type (`AKP`) and registers ML-DSA algorithms via jwx's extension point system. ML-DSA algorithms are registered with `dsig` as Custom family algorithms and mapped through `jwsbb`. The `jws.Signer`/`jws.Verifier` implementations unwrap JWK keys and delegate to `jwsbb.Sign`/`jwsbb.Verify`, which dispatches through `dsig`.

### JWK Key Type: AKP (Algorithm Key Pair)

Follows [draft-ietf-cose-dilithium](https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html):

- `kty`: `"AKP"` (read-only)
- `alg`: `"ML-DSA-44"` / `"ML-DSA-65"` / `"ML-DSA-87"` (REQUIRED)
- `pub`: base64url-encoded public key bytes (REQUIRED)
- `priv`: base64url-encoded 32-byte seed (private keys only)
- Thumbprint fields: `alg`, `kty`, `pub` in lexicographic order

### Registration Points

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterKeyType()` | Register AKP key type |
| `jwa` | `RegisterSignatureAlgorithm()` | Register ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| `jwk` | `RegisterKeyParser()` | Parse AKP JWK JSON |
| `jwk` | `RegisterProbeField()` | Register `priv` probe for pub/priv distinction |
| `jwk` | `RegisterKeyImporter()` | Convert `*mldsa.PrivateKey`/`*mldsa.PublicKey` to `jwk.Key` |
| `jwk` | `RegisterKeyExporter()` | Convert `jwk.Key` to raw ML-DSA keys |
| `dsig` | `RegisterAlgorithm()` | Register ML-DSA as Custom family dsig algorithms |
| `jwsbb` | `RegisterDsigAlgorithm()` | Map JWS algorithm names to dsig algorithm names |
| `jws` | `RegisterSigner()` | ML-DSA signing (unwrap JWK, delegate to jwsbb) |
| `jws` | `RegisterVerifier()` | ML-DSA verification (unwrap JWK, delegate to jwsbb) |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate algorithms with AKP key type |

### Key Implementation Note

The `akpPublicKey` and `akpPrivateKey` types implement the full `jwk.Key` interface from scratch (including all standard JWK header fields). This is necessary because jwx does not provide an embeddable base key type for external modules. This boilerplate could be refactored if jwx adds such a type.

### Dependency on filippo.io/mldsa

This module currently depends on `filippo.io/mldsa` for the underlying ML-DSA implementation. Once Go ships `crypto/mldsa` (tracking: https://github.com/golang/go/issues/77626), this module will migrate to the standard library implementation and this separate module may become unnecessary — the support could move directly into jwx.

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `mldsa.go` | Package doc, algorithm constants, `init()` registration, key parser/importer/exporter |
| `key.go` | `akpPublicKey` and `akpPrivateKey` implementing `jwk.Key` |
| `signer.go` | `mldsaSigner` implementing `jws.Signer` |
| `verifier.go` | `mldsaVerifier` implementing `jws.Verifier` |
| `mldsa_test.go` | Tests |
