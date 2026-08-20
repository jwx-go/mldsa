# ML-DSA Extension for JWX

## Overview

This module (`github.com/jwx-go/mldsa/v4`) provides ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) support for `github.com/lestrrat-go/jwx`.

ML-DSA is a post-quantum digital signature scheme. This module bridges the `filippo.io/mldsa` implementation into jwx's algorithm registration system, enabling ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.

## Architecture

The `AKP` (Algorithm Key Pair) `jwk.Key` type is provided by the jwx main module itself. This companion only plugs ML-DSA into jwx's extension points: it registers the ML-DSA signature algorithms, raw-key importers/exporters, and `jws.Signer`/`jws.Verifier` implementations. ML-DSA algorithms are registered with `dsig` as Custom family algorithms and mapped through `jwsbb`. The signer/verifier unwrap the AKP JWK key and delegate to `jwsbb.Sign`/`jwsbb.Verify`, which dispatches through `dsig`.

That describes standalone mode. When jwx provides ML-DSA itself, this module registers a narrower set instead — see "Interop mode on native ML-DSA" below.

### JWK Key Type: AKP (Algorithm Key Pair)

AKP follows [draft-ietf-cose-dilithium](https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html) and is defined in jwx's main `jwk` package — this module does not re-implement it:

- `kty`: `"AKP"`
- `alg`: `"ML-DSA-44"` / `"ML-DSA-65"` / `"ML-DSA-87"` (REQUIRED)
- `pub`: base64url-encoded public key bytes (REQUIRED)
- `priv`: base64url-encoded 32-byte seed (private keys only)
- Thumbprint fields: `alg`, `kty`, `pub` in lexicographic order

### Interop mode on native ML-DSA

`init()` first probes `dsig.GetAlgorithmInfo("ML-DSA-44")`. A hit means jwx already registered ML-DSA, which happens from **v4.4.0** on when built with **Go 1.27** or later, where `crypto/mldsa` is in the standard library. Re-registering the same names would make `dsig.RegisterAlgorithm` fail and this package panic at import, so the algorithms are left to jwx.

The key types are not. On a hit, `registerInterop` (in `interop_go127.go`) installs a bridge that converts `filippo.io/mldsa` keys to `crypto/mldsa` and delegates to jwx. `InteropMode()` reports whether that path was taken.

Both versions are required, so there are three cases where this module implements ML-DSA itself: jwx v4.3.0 or earlier on any toolchain, jwx v4.4.0 or later on Go 1.26 (its ML-DSA files are `//go:build go1.27`), and any jwx on Go 1.26.

The probe is on `dsig` rather than on the Go version or the jwx version deliberately. It reports what is actually registered, so no version table has to be kept in sync here, and the module stays correct against jwx releases that did not exist when it was written.

#### What interop mode registers

Interop touches nothing that `dsig` owns, because `dsig` rejects a duplicate algorithm name. It registers only where dispatch is by Go type or by algorithm object:

| JWX Package | Registration | Interop behavior |
|-------------|--------------|------------------|
| `jwk` | `RegisterKeyImporter()` | Added for the `filippo.io/mldsa` types; jwx registered the `crypto/mldsa` types, and importers are keyed by Go type, so there is no collision. |
| `jwk` | `RegisterKeyExporter()` | Tried before jwx's, and returns `ContinueError()` for every hint that is not an explicit `filippo.io/mldsa` type. |
| `jws` | `RegisterSigner()` / `RegisterVerifier()` | Overrides jwx's pair (`signerDB.Store` is last-write-wins), converts a filippo key, and delegates. |

Two rules follow:

- **`crypto/mldsa` always wins.** `jwk.Export[any]` passes a nil hint, which the interop exporter declines, so the untyped export yields a `crypto/mldsa` key. Only `jwk.Export[*mldsa.PrivateKey]` naming the filippo type yields a filippo key.
- **Interop stops below `jws`.** `jwsbb.Sign`, `jwsbb.Verify`, and the `dsig` layer are `crypto/mldsa`-only, since they dispatch on the algorithm name alone and `dsig` v1.4.0 owns those names.

Capturing jwx's signer via `jws.SignerFor` **before** calling `jws.RegisterSigner` is mandatory. Looking it up afterwards returns the interop wrapper, and the delegation recurses until the stack runs out.

Conversion is exact in both directions for all three parameter sets, because both libraries encode a private key as the FIPS 204 seed. It costs one key expansion per operation, roughly 208µs against 466µs to sign, and it is paid only by a caller still passing a raw filippo key.

### Registration Points

The table below lists standalone mode, which `mldsa.go`'s `init()` installs when the `dsig` probe above misses. Interop mode registers a subset, listed in "What interop mode registers". Key type registration, AKP JWK parsing, and the `priv` probe field are handled by jwx itself — this module only adds the ML-DSA-specific bindings below.

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

On Go 1.26, `GOEXPERIMENT=jsonv2` is required (jwx v4 dependency). On Go 1.27 it must NOT be set, because that toolchain already ships `encoding/json/v2`.

```
GOEXPERIMENT=jsonv2 go test ./...   # Go 1.26
go test ./...                       # Go 1.27
```

The toolchain selects the mode on its own. `go.mod` requires jwx v4.4.0 or later, whose ML-DSA files are `//go:build go1.27`, so the Go 1.26 command above exercises standalone mode and the Go 1.27 one exercises interop mode. Neither needs a `go get` first.

Set `JWX_MLDSA_EXPECT_INTEROP` to `1` or `0` to assert which mode the run landed in. `TestInteropModeMatchesExpectation` then fails on a mismatch. Without it, a run in the wrong mode goes green having skipped every test that mode-specific coverage lives in.

### Workflows

| Workflow | Toolchain | Mode |
|----------|-----------|------|
| `ci.yml` | `go.mod` (Go 1.26), `GOEXPERIMENT=jsonv2` | Standalone |
| `go127.yml` job `interop` | Go 1.27 | Interop |

`ci.yml` is synced from the shared companion template, so Go 1.27 coverage lives in `go127.yml` instead of being added there.

There is no job covering standalone mode on Go 1.27, because no supported configuration produces it: that needs jwx v4.3.0 or earlier, which `go.mod` no longer allows.

**Releasing a jwx version that changes which mode a toolchain lands in means updating `go127.yml` in the same change.** The `JWX_MLDSA_EXPECT_INTEROP` assertions are pinned to the modes above, so a jwx bump that moves a toolchain across the boundary turns this repo's default branch red until the workflow follows. That is what happened when jwx v4.4.0 shipped.

## Files

| File | Purpose |
|------|---------|
| `mldsa.go` | Package doc, algorithm constants, `init()` registration, `InteropMode()`, raw-key importers/exporter, `dsig` algorithm adapter |
| `signer.go` | `mldsaSigner` implementing `jws.Signer` |
| `verifier.go` | `mldsaVerifier` implementing `jws.Verifier` |
| `interop_go127.go` | Interop-mode registration and the `filippo.io/mldsa` to `crypto/mldsa` conversion (`//go:build go1.27`) |
| `interop_pre_go127.go` | Interop-mode stub for Go 1.26, where there is no `crypto/mldsa` to convert to |
| `mldsa_test.go` | Tests |
| `interop_go127_test.go` | Interop-mode tests, skipped unless jwx provides ML-DSA natively |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
