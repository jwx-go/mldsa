# ML-DSA Extension for JWX

## Overview

This module (`github.com/jwx-go/mldsa/v4`) provides ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) support for `github.com/lestrrat-go/jwx`.

ML-DSA is a post-quantum digital signature scheme. This module bridges the `filippo.io/mldsa` implementation into jwx's algorithm registration system, enabling ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.

## Architecture

The `AKP` (Algorithm Key Pair) `jwk.Key` type is provided by the jwx main module itself. This companion only plugs ML-DSA into jwx's extension points: it registers the ML-DSA signature algorithms, raw-key importers/exporters, and `jws.Signer`/`jws.Verifier` implementations. ML-DSA algorithms are registered with `dsig` as Custom family algorithms and mapped through `jwsbb`. The signer/verifier unwrap the AKP JWK key and delegate to `jwsbb.Sign`/`jwsbb.Verify`, which dispatches through `dsig`.

### JWK Key Type: AKP (Algorithm Key Pair)

AKP follows [draft-ietf-cose-dilithium](https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html) and is defined in jwx's main `jwk` package — this module does not re-implement it:

- `kty`: `"AKP"`
- `alg`: `"ML-DSA-44"` / `"ML-DSA-65"` / `"ML-DSA-87"` (REQUIRED)
- `pub`: base64url-encoded public key bytes (REQUIRED)
- `priv`: base64url-encoded 32-byte seed (private keys only)
- Thumbprint fields: `alg`, `kty`, `pub` in lexicographic order

### Registration Points

All registrations happen in `mldsa.go`'s `init()`. Key type registration, AKP JWK parsing, and the `priv` probe field are handled by jwx itself — this module only adds the ML-DSA-specific bindings below.

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterSignatureAlgorithm()` | Register ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| `jwk` | `RegisterKeyImporter()` | Convert `*mldsa.PrivateKey` / `*mldsa.PublicKey` to `jwk.Key` |
| `jwk` | `RegisterKeyExporter()` | Convert AKP `jwk.Key` (per-alg `KeyKind` `"AKP:ML-DSA-<n>"`) to raw ML-DSA keys |
| `dsig` | `RegisterAlgorithm()` | Register ML-DSA as Custom family dsig algorithms |
| `jwsbb` | `RegisterDsigAlgorithm()` | Map JWS algorithm names to dsig algorithm names |
| `jws` | `RegisterSigner()` | ML-DSA signing (unwrap JWK, delegate to jwsbb) |
| `jws` | `RegisterVerifier()` | ML-DSA verification (unwrap JWK, delegate to jwsbb) |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate algorithms with `jwa.AKP()` |

### Dependency on filippo.io/mldsa

This module depends on `filippo.io/mldsa` for the underlying ML-DSA implementation. Upstream has published no semver tags; the dependency is pinned to pseudo-version `v0.0.0-20260215214346-43d0283efc3e` (commit `43d0283efc3e`, 2026-02-15). Cryptographic integrity is anchored by the `h1:` hashes in `go.sum` — do not bump without updating both. The pin will be revisited when either (a) filippo.io/mldsa cuts a tagged release, or (b) Go ships `crypto/mldsa` (https://github.com/golang/go/issues/77626), at which point this module migrates to the standard library and may be deprecated entirely. See `mldsa.go` package doc for the bridge rationale.

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `mldsa.go` | Package doc, algorithm constants, `init()` registration, raw-key importers/exporter, `dsig` algorithm adapter |
| `signer.go` | `mldsaSigner` implementing `jws.Signer` |
| `verifier.go` | `mldsaVerifier` implementing `jws.Verifier` |
| `mldsa_test.go` | Tests |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
