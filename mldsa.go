// Package mldsa provides ML-DSA (FIPS 204) support for the jwx library.
//
// ML-DSA is a post-quantum digital signature scheme. This module bridges
// [filippo.io/mldsa] into jwx's algorithm registration system, enabling
// ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.
//
// This exists as a separate module because Go's standard library does not
// yet include ML-DSA support, requiring the external [filippo.io/mldsa]
// dependency. To avoid imposing this dependency on all jwx users, ML-DSA
// support is provided as an opt-in extension. Once Go ships [crypto/mldsa]
// (see https://github.com/golang/go/issues/77626), this module will migrate
// to the standard library implementation and ML-DSA support may move directly
// into jwx, at which point this module will be deprecated.
//
// Import this package for its side effects to enable ML-DSA support:
//
//	import _ "github.com/jwx-go/mldsa/v4"
//
// This registers ML-DSA-44/65/87 signature algorithms,
// JWK key import/export, and JWS signing/verification for AKP keys.
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules.
package mldsa

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// MLDSA44 returns the ML-DSA-44 signature algorithm.
func MLDSA44() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm("ML-DSA-44")
}

// MLDSA65 returns the ML-DSA-65 signature algorithm.
func MLDSA65() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm("ML-DSA-65")
}

// MLDSA87 returns the ML-DSA-87 signature algorithm.
func MLDSA87() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm("ML-DSA-87")
}

// paramsForAlg returns the mldsa.Parameters for the given algorithm string.
func paramsForAlg(alg string) (*mldsa.Parameters, error) {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44(), nil
	case "ML-DSA-65":
		return mldsa.MLDSA65(), nil
	case "ML-DSA-87":
		return mldsa.MLDSA87(), nil
	default:
		return nil, fmt.Errorf(`unknown ML-DSA algorithm %q`, alg)
	}
}

func init() {
	// Register signature algorithms
	panicOnRegistrationError(jwa.RegisterSignatureAlgorithm(MLDSA44(), MLDSA65(), MLDSA87()))

	// Register key importers for raw mldsa key types
	panicOnRegistrationError(jwk.RegisterKeyImporter(importMLDSAPrivateKey))
	panicOnRegistrationError(jwk.RegisterKeyImporter(importMLDSAPublicKey))

	// Register key exporters for ML-DSA algorithm-specific key kinds.
	// jwx v4's AKP key returns KeyKind "AKP:<alg>", so we register per-algorithm.
	// The fallback "AKP" exporter in jwx v4 handles ML-KEM only.
	for _, algName := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+algName), jwk.KeyExportFunc(exportMLDSAKey)))
	}

	// Associate algorithms with the AKP key type
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.AKP(), MLDSA44()))
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.AKP(), MLDSA65()))
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.AKP(), MLDSA87()))

	// Register dsig algorithms (Custom family) and jwsbb mappings
	for _, entry := range []struct {
		name   string
		alg    jwa.SignatureAlgorithm
		params *mldsa.Parameters
	}{
		{"ML-DSA-44", MLDSA44(), mldsa.MLDSA44()},
		{"ML-DSA-65", MLDSA65(), mldsa.MLDSA65()},
		{"ML-DSA-87", MLDSA87(), mldsa.MLDSA87()},
	} {
		if err := dsig.RegisterAlgorithm(entry.name, dsig.AlgorithmInfo{
			Family: dsig.Custom,
			Meta:   &mldsaDsigAlgorithm{params: entry.params},
		}); err != nil {
			panic(fmt.Sprintf("jwx-go/mldsa: failed to register dsig algorithm %s: %s", entry.name, err))
		}
		panicOnRegistrationError(jwsbb.RegisterDsigAlgorithm(entry.name, entry.name))

		panicOnRegistrationError(jws.RegisterSigner(entry.alg, &mldsaSigner{algName: entry.name, params: entry.params}))
		panicOnRegistrationError(jws.RegisterVerifier(entry.alg, &mldsaVerifier{algName: entry.name, params: entry.params}))
	}
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/mldsa: registration failed: %s", err))
	}
}

// importMLDSAPrivateKey converts a *mldsa.PrivateKey to a jwk.Key.
func importMLDSAPrivateKey(raw *mldsa.PrivateKey) (jwk.Key, error) {
	pub := raw.PublicKey()
	params := pub.Parameters()

	key, err := jwkunsafe.NewKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, params.String()); err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, pub.Bytes()); err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	if err := key.Set(jwk.AKPPrivKey, raw.Bytes()); err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	return key, nil
}

// importMLDSAPublicKey converts a *mldsa.PublicKey to a jwk.Key.
func importMLDSAPublicKey(raw *mldsa.PublicKey) (jwk.Key, error) {
	params := raw.Parameters()

	key, err := jwkunsafe.NewPublicKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, params.String()); err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, raw.Bytes()); err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	return key, nil
}

// mldsaDsigAlgorithm implements dsig.Signer and dsig.Verifier for ML-DSA.
// It handles raw *mldsa.PrivateKey / *mldsa.PublicKey only — JWK key
// unwrapping is done by the jws.Signer/Verifier layer above.
type mldsaDsigAlgorithm struct {
	params *mldsa.Parameters
}

func (a *mldsaDsigAlgorithm) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`mldsa dsig.Sign: expected *mldsa.PrivateKey, got %T`, key)
	}
	return sk.Sign(nil, payload, nil)
}

// SignWithOpts implements dsig.SignerWithOpts. If opts is an *mldsa.Options,
// its Context field is forwarded to filippo.io/mldsa, enabling callers
// (notably the composite-signature scheme in github.com/jwx-go/compsig)
// to supply the per-algorithm domain-separation context required by the
// JOSE composite-signatures draft.
func (a *mldsaDsigAlgorithm) SignWithOpts(key any, payload []byte, opts crypto.SignerOpts, _ io.Reader) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`mldsa dsig.SignWithOpts: expected *mldsa.PrivateKey, got %T`, key)
	}
	return sk.Sign(nil, payload, opts)
}

func (a *mldsaDsigAlgorithm) Verify(key any, payload, signature []byte) error {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		return mldsa.Verify(k, payload, signature, nil)
	case *mldsa.PrivateKey:
		return mldsa.Verify(k.PublicKey(), payload, signature, nil)
	default:
		return fmt.Errorf(`mldsa dsig.Verify: expected *mldsa.PublicKey or *mldsa.PrivateKey, got %T`, key)
	}
}

// VerifyWithOpts implements dsig.VerifierWithOpts. The Context from an
// *mldsa.Options (if non-nil) is forwarded to filippo.io/mldsa.Verify.
func (a *mldsaDsigAlgorithm) VerifyWithOpts(key any, payload, signature []byte, opts crypto.SignerOpts) error {
	mldsaOpts, _ := opts.(*mldsa.Options)
	switch k := key.(type) {
	case *mldsa.PublicKey:
		return mldsa.Verify(k, payload, signature, mldsaOpts)
	case *mldsa.PrivateKey:
		return mldsa.Verify(k.PublicKey(), payload, signature, mldsaOpts)
	default:
		return fmt.Errorf(`mldsa dsig.VerifyWithOpts: expected *mldsa.PublicKey or *mldsa.PrivateKey, got %T`, key)
	}
}

// exportMLDSAKey converts a jwk.Key to a raw mldsa key type.
func exportMLDSAKey(key jwk.Key, hint any) (any, error) {
	algV, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`missing "alg" field`)
	}

	params, err := paramsForAlg(algV.String())
	if err != nil {
		return nil, jwk.ContinueError()
	}

	pubV, ok := key.Field(jwk.AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	pubBytes, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`"pub" field is not []byte`)
	}

	privV, hasPriv := key.Field(jwk.AKPPrivKey)
	if hasPriv {
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"priv" field is not []byte`)
		}

		sk, err := mldsa.NewPrivateKey(params, privBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA private key: %w`, err)
		}

		if derivedPub := sk.PublicKey().Bytes(); !bytes.Equal(derivedPub, pubBytes) {
			return nil, fmt.Errorf(`"pub" does not match derived public key`)
		}

		return sk, nil
	}

	pk, err := mldsa.NewPublicKey(params, pubBytes)
	if err != nil {
		return nil, fmt.Errorf(`failed to construct ML-DSA public key: %w`, err)
	}
	return pk, nil
}
