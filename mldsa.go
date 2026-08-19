// Package mldsa provides ML-DSA (FIPS 204) support for the jwx library.
//
// ML-DSA is a post-quantum digital signature scheme. This module bridges
// [filippo.io/mldsa] into jwx's algorithm registration system, enabling
// ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.
//
// Deprecated: Go 1.27 ships crypto/mldsa, and jwx implements ML-DSA natively
// from that version on. On Go 1.27 with a jwx release that has native ML-DSA,
// importing this package does nothing: init detects the existing registration
// and stands down, so the import is harmless but pointless. Drop it, replace
// [filippo.io/mldsa] with crypto/mldsa, and use jwa.MLDSA44, jwa.MLDSA65, and
// jwa.MLDSA87 in place of this package's accessors. Raw *mldsa.PrivateKey and
// *mldsa.PublicKey values must come from crypto/mldsa in that setup — jwx's
// signer does not accept filippo.io/mldsa key types. This module stays
// supported for as long as jwx supports Go 1.26.
//
// This exists as a separate module because Go's standard library did not
// include ML-DSA support before 1.27, requiring the external
// [filippo.io/mldsa] dependency. To avoid imposing that dependency on all jwx
// users, ML-DSA support was provided as an opt-in extension.
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

// Algorithm name strings for the three ML-DSA parameter sets, as they
// appear in the JWS "alg" header and in dsig/jwsbb registrations.
const (
	algMLDSA44 = "ML-DSA-44"
	algMLDSA65 = "ML-DSA-65"
	algMLDSA87 = "ML-DSA-87"
)

// MLDSA44 returns the ML-DSA-44 signature algorithm.
func MLDSA44() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm(algMLDSA44)
}

// MLDSA65 returns the ML-DSA-65 signature algorithm.
func MLDSA65() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm(algMLDSA65)
}

// MLDSA87 returns the ML-DSA-87 signature algorithm.
func MLDSA87() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm(algMLDSA87)
}

// requireParamsMatch verifies that a caller-supplied key's parameter set
// matches the algorithm's registered parameter set. filippo.io/mldsa
// returns package-level singletons from MLDSA44/65/87, so pointer
// equality is sufficient. Mismatch indicates an alg/key confusion
// attempt (EXT-010).
func requireParamsMatch(got, want *mldsa.Parameters) error {
	if got != want {
		return fmt.Errorf(`ML-DSA parameter set mismatch: key is %s, algorithm is %s`, got, want)
	}
	return nil
}

// paramsForAlg returns the mldsa.Parameters for the given algorithm string.
func paramsForAlg(alg string) (*mldsa.Parameters, error) {
	switch alg {
	case algMLDSA44:
		return mldsa.MLDSA44(), nil
	case algMLDSA65:
		return mldsa.MLDSA65(), nil
	case algMLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		return nil, fmt.Errorf(`unknown ML-DSA algorithm %q`, alg)
	}
}

func init() {
	// Stand down when ML-DSA is already registered. From Go 1.27 on, jwx
	// implements ML-DSA itself on top of crypto/mldsa, and registering these
	// names a second time would fail — dsig rejects a duplicate algorithm
	// name, which this package turns into an import-time panic. Yielding is
	// the right call rather than racing: jws.Sign and jws.Verify dispatch on
	// the algorithm name, so whoever registered first owns the behavior, and
	// jwx's own implementation is the one its key types are built for.
	//
	// The probe is on dsig rather than on the Go version so that this works
	// against any jwx release: an older jwx on Go 1.27 registers nothing, and
	// this package still provides ML-DSA as it always has.
	if _, ok := dsig.GetAlgorithmInfo(algMLDSA44); ok {
		return
	}

	// Register signature algorithms
	panicOnRegistrationError(jwa.RegisterSignatureAlgorithm(MLDSA44(), MLDSA65(), MLDSA87()))

	// Register key importers for raw mldsa key types
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mldsa.PrivateKey](importMLDSAPrivateKey)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mldsa.PublicKey](importMLDSAPublicKey)))

	// Register key exporters for ML-DSA algorithm-specific key kinds.
	// jwx v4's AKP key returns KeyKind "AKP:<alg>", so we register per-algorithm.
	// The fallback "AKP" exporter in jwx v4 handles ML-KEM only.
	for _, algName := range []string{algMLDSA44, algMLDSA65, algMLDSA87} {
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
		{algMLDSA44, MLDSA44(), mldsa.MLDSA44()},
		{algMLDSA65, MLDSA65(), mldsa.MLDSA65()},
		{algMLDSA87, MLDSA87(), mldsa.MLDSA87()},
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
	if err := requireParamsMatch(sk.PublicKey().Parameters(), a.params); err != nil {
		return nil, fmt.Errorf(`mldsa dsig.Sign: %w`, err)
	}
	return sk.Sign(nil, payload, nil)
}

// SignWithOpts implements dsig.SignerWithOpts. If opts is non-nil it must be
// of concrete type *mldsa.Options; its Context field is forwarded to
// filippo.io/mldsa, enabling callers (notably the composite-signature scheme
// in github.com/jwx-go/compsig) to supply the per-algorithm domain-separation
// context required by the JOSE composite-signatures draft. A non-nil opts of
// any other type is rejected with an error rather than silently coerced to
// nil — a silent coerce would make a caller believe their Context was being
// honored while ctx="" was actually being used, a signature-substitution
// vector for composite signatures.
func (a *mldsaDsigAlgorithm) SignWithOpts(key any, payload []byte, opts crypto.SignerOpts, _ io.Reader) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`mldsa dsig.SignWithOpts: expected *mldsa.PrivateKey, got %T`, key)
	}
	if err := requireParamsMatch(sk.PublicKey().Parameters(), a.params); err != nil {
		return nil, fmt.Errorf(`mldsa dsig.SignWithOpts: %w`, err)
	}
	if opts != nil {
		if _, ok := opts.(*mldsa.Options); !ok {
			return nil, fmt.Errorf(`mldsa dsig.SignWithOpts: expected *mldsa.Options, got %T`, opts)
		}
	}
	return sk.Sign(nil, payload, opts)
}

func (a *mldsaDsigAlgorithm) Verify(key any, payload, signature []byte) error {
	pk, err := dsigPublicKey(key)
	if err != nil {
		return fmt.Errorf(`mldsa dsig.Verify: %w`, err)
	}
	if err := requireParamsMatch(pk.Parameters(), a.params); err != nil {
		return fmt.Errorf(`mldsa dsig.Verify: %w`, err)
	}
	return mldsa.Verify(pk, payload, signature, nil)
}

// VerifyWithOpts implements dsig.VerifierWithOpts. If opts is non-nil it
// must be of concrete type *mldsa.Options; its Context field is forwarded to
// filippo.io/mldsa.Verify. A non-nil opts of any other type is rejected
// rather than silently coerced to nil — see SignWithOpts for the rationale.
func (a *mldsaDsigAlgorithm) VerifyWithOpts(key any, payload, signature []byte, opts crypto.SignerOpts) error {
	pk, err := dsigPublicKey(key)
	if err != nil {
		return fmt.Errorf(`mldsa dsig.VerifyWithOpts: %w`, err)
	}
	if err := requireParamsMatch(pk.Parameters(), a.params); err != nil {
		return fmt.Errorf(`mldsa dsig.VerifyWithOpts: %w`, err)
	}
	var mldsaOpts *mldsa.Options
	if opts != nil {
		var ok bool
		mldsaOpts, ok = opts.(*mldsa.Options)
		if !ok {
			return fmt.Errorf(`mldsa dsig.VerifyWithOpts: expected *mldsa.Options, got %T`, opts)
		}
	}
	return mldsa.Verify(pk, payload, signature, mldsaOpts)
}

// dsigPublicKey normalizes the key types accepted by the dsig Verify
// surface to a *mldsa.PublicKey.
func dsigPublicKey(key any) (*mldsa.PublicKey, error) {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		return k, nil
	case *mldsa.PrivateKey:
		return k.PublicKey(), nil
	default:
		return nil, fmt.Errorf(`expected *mldsa.PublicKey or *mldsa.PrivateKey, got %T`, key)
	}
}

// exportMLDSAKey converts a jwk.Key to a raw mldsa key type.
func exportMLDSAKey(key jwk.Key, _ any) (any, error) {
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
