//go:build go1.27

package mldsa

import (
	stdmldsa "crypto/mldsa"
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// registerInterop installs the filippo.io/mldsa bridge on top of an ML-DSA
// implementation jwx already registered, and reports that interop mode is
// active.
//
// Nothing here touches dsig. dsig rejects a duplicate algorithm name and it
// already owns ML-DSA-44/65/87 in this configuration, so the jwsbb and dsig
// layers stay crypto/mldsa-only. Interop lives one level up, in jwk and jws,
// where dispatch is by Go type and by algorithm object instead of by
// algorithm name alone.
func registerInterop() bool {
	// Importers are keyed by Go type, and jwx registered the crypto/mldsa
	// types, so these two are additions and cannot collide.
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mldsa.PrivateKey](importMLDSAPrivateKey)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mldsa.PublicKey](importMLDSAPublicKey)))

	// Exporters for one KeyKind are tried in reverse registration order, so
	// this one runs before jwx's. It declines everything that does not name a
	// filippo.io/mldsa type, which leaves crypto/mldsa as the default.
	for _, algName := range []string{algMLDSA44, algMLDSA65, algMLDSA87} {
		panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+algName), jwk.KeyExportFunc(exportInteropKey)))
	}

	for _, alg := range []jwa.SignatureAlgorithm{MLDSA44(), MLDSA65(), MLDSA87()} {
		// Capture jwx's implementation before replacing it. jws.RegisterSigner
		// is last-write-wins, so looking the signer up after the override
		// would return this wrapper and the delegation below would recurse
		// until the stack ran out.
		signer, err := jws.SignerFor(alg)
		if err != nil {
			panic(fmt.Sprintf("jwx-go/mldsa: no signer to delegate to for %s: %s", alg, err))
		}
		verifier, err := jws.VerifierFor(alg)
		if err != nil {
			panic(fmt.Sprintf("jwx-go/mldsa: no verifier to delegate to for %s: %s", alg, err))
		}

		panicOnRegistrationError(jws.RegisterSigner(alg, &interopSigner{native: signer}))
		panicOnRegistrationError(jws.RegisterVerifier(alg, &interopVerifier{native: verifier}))
	}

	return true
}

// stdParamsForAlg returns the crypto/mldsa parameter set for the given
// algorithm name.
func stdParamsForAlg(alg string) (stdmldsa.Parameters, error) {
	switch alg {
	case algMLDSA44:
		return stdmldsa.MLDSA44(), nil
	case algMLDSA65:
		return stdmldsa.MLDSA65(), nil
	case algMLDSA87:
		return stdmldsa.MLDSA87(), nil
	default:
		return stdmldsa.Parameters{}, fmt.Errorf(`unknown ML-DSA algorithm %q`, alg)
	}
}

// toStdlibKey converts a filippo.io/mldsa key into its crypto/mldsa
// counterpart. Both libraries encode a private key as the FIPS 204 seed and a
// public key as the encoded public key, so the conversion is exact.
//
// Any other value is returned untouched, which is what lets crypto/mldsa keys
// and jwk.Key values reach jwx unchanged.
//
// The parameter set comes from the key itself, never from the algorithm being
// signed under. A key whose parameter set disagrees with the algorithm has to
// reach jwx intact so that jwx's own check rejects it; picking the
// algorithm's parameter set here would either fail with a confusing length
// error or, worse, quietly reinterpret the key.
func toStdlibKey(key any) (any, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		params, err := stdParamsForAlg(k.PublicKey().Parameters().String())
		if err != nil {
			return nil, err
		}
		return stdmldsa.NewPrivateKey(params, k.Bytes())
	case *mldsa.PublicKey:
		params, err := stdParamsForAlg(k.Parameters().String())
		if err != nil {
			return nil, err
		}
		return stdmldsa.NewPublicKey(params, k.Bytes())
	default:
		return key, nil
	}
}

// isFilippoHint reports whether an exporter hint names a filippo.io/mldsa
// key type. A nil hint, which is what jwk.Export[any] passes, is not one.
func isFilippoHint(hint any) bool {
	switch hint.(type) {
	case *mldsa.PrivateKey, *mldsa.PublicKey:
		return true
	default:
		return false
	}
}

// exportInteropKey answers only for a caller that asked for a
// filippo.io/mldsa key by type, and defers to jwx's crypto/mldsa exporter for
// everything else.
func exportInteropKey(key jwk.Key, hint any) (any, error) {
	if !isFilippoHint(hint) {
		return nil, jwk.ContinueError()
	}

	// Deliberately no special case for a public hint against a private JWK.
	// jwx's own exporters, ML-DSA and RSA alike, return a private key
	// whenever the JWK carries "priv" and let jwk.Export fail the type
	// assertion. Answering that case here would make filippo keys behave
	// differently from crypto/mldsa ones, which is the asymmetry interop mode
	// exists to remove.
	return exportMLDSAKey(key, hint)
}

// interopSigner converts a filippo.io/mldsa private key and lets jwx sign.
type interopSigner struct {
	native jws.Signer
}

func (s *interopSigner) Sign(key any, payload []byte) ([]byte, error) {
	converted, err := toStdlibKey(key)
	if err != nil {
		return nil, fmt.Errorf(`mldsa.Sign: %w`, err)
	}
	return s.native.Sign(converted, payload)
}

// interopVerifier converts a filippo.io/mldsa key and lets jwx verify.
type interopVerifier struct {
	native jws.Verifier
}

func (v *interopVerifier) Verify(key any, payload, signature []byte) error {
	converted, err := toStdlibKey(key)
	if err != nil {
		return fmt.Errorf(`mldsa.Verify: %w`, err)
	}
	return v.native.Verify(converted, payload, signature)
}
