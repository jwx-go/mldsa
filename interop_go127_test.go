//go:build go1.27

package mldsa_test

import (
	stdmldsa "crypto/mldsa"
	"testing"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	jwxmldsa "github.com/jwx-go/mldsa/v4"
)

// requireInterop skips a test unless this build actually took the interop
// path. Interop needs jwx to have registered ML-DSA itself, which only
// happens on jwx v4.4.0 and later; against an older jwx this package still
// owns the algorithms and the interop behavior does not apply.
func requireInterop(t *testing.T) {
	t.Helper()
	if !jwxmldsa.InteropMode() {
		t.Skip("jwx does not provide ML-DSA natively in this build; this package owns it")
	}
}

func stdParamsFor(t *testing.T, params *mldsa.Parameters) stdmldsa.Parameters {
	t.Helper()
	switch params.String() {
	case algMLDSA44:
		return stdmldsa.MLDSA44()
	case algMLDSA65:
		return stdmldsa.MLDSA65()
	case algMLDSA87:
		return stdmldsa.MLDSA87()
	}
	t.Fatalf("no crypto/mldsa parameter set for %s", params)
	return stdmldsa.Parameters{}
}

// The point of interop mode: a caller who has not migrated keeps passing
// filippo.io/mldsa keys and everything still works.
func TestInteropFilippoKeyThroughJWS(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	for _, params := range []*mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			alg := jwa.NewSignatureAlgorithm(params.String())
			sk, err := mldsa.GenerateKey(params)
			require.NoError(t, err)

			signed, err := jws.Sign([]byte("payload"), jws.WithKey(alg, sk))
			require.NoError(t, err)

			got, err := jws.Verify(signed, jws.WithKey(alg, sk.PublicKey()))
			require.NoError(t, err)
			require.Equal(t, []byte("payload"), got)
		})
	}
}

// A caller who has migrated must be unaffected by this package being imported.
func TestInteropStdlibKeyThroughJWS(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	sk, err := stdmldsa.GenerateKey(stdmldsa.MLDSA65())
	require.NoError(t, err)

	signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwxmldsa.MLDSA65(), sk))
	require.NoError(t, err)

	got, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), sk.PublicKey()))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)
}

// The two backends must produce and accept each other's signatures, otherwise
// "interop" is only a compile-time property.
func TestInteropCrossBackendSignatures(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	fsk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	ssk, err := stdmldsa.NewPrivateKey(stdmldsa.MLDSA65(), fsk.Bytes())
	require.NoError(t, err)
	require.Equal(t, fsk.PublicKey().Bytes(), ssk.PublicKey().Bytes())

	byFilippo, err := jws.Sign([]byte("payload"), jws.WithKey(jwxmldsa.MLDSA65(), fsk))
	require.NoError(t, err)
	_, err = jws.Verify(byFilippo, jws.WithKey(jwxmldsa.MLDSA65(), ssk.PublicKey()))
	require.NoError(t, err)

	byStdlib, err := jws.Sign([]byte("payload"), jws.WithKey(jwxmldsa.MLDSA65(), ssk))
	require.NoError(t, err)
	_, err = jws.Verify(byStdlib, jws.WithKey(jwxmldsa.MLDSA65(), fsk.PublicKey()))
	require.NoError(t, err)
}

func TestInteropImportFilippoKey(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	t.Run("private", func(t *testing.T) {
		t.Parallel()
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		require.Equal(t, jwa.AKP(), key.KeyType())

		signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwxmldsa.MLDSA44(), key))
		require.NoError(t, err)

		pub, err := key.PublicKey()
		require.NoError(t, err)
		_, err = jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), pub))
		require.NoError(t, err)
	})

	t.Run("public", func(t *testing.T) {
		t.Parallel()
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](sk.PublicKey())
		require.NoError(t, err)
		require.Equal(t, jwa.AKP(), key.KeyType())
		_, hasPriv := key.Field(jwk.AKPPrivKey)
		require.False(t, hasPriv)
	})
}

// crypto/mldsa always wins when the requested type does not name a backend.
func TestInteropExportPrefersStdlib(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)

	raw, err := jwk.Export[any](key)
	require.NoError(t, err)
	require.IsType(t, &stdmldsa.PrivateKey{}, raw)
}

// Naming a backend explicitly still gets that backend.
func TestInteropExportByRequestedType(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)

	t.Run("filippo private", func(t *testing.T) {
		t.Parallel()
		got, err := jwk.Export[*mldsa.PrivateKey](key)
		require.NoError(t, err)
		require.Equal(t, sk.Bytes(), got.Bytes())
	})

	t.Run("filippo public", func(t *testing.T) {
		t.Parallel()
		// From the public JWK, matching what the stdlib case below does.
		// jwx's exporters return a private key whenever the JWK carries
		// "priv", regardless of the requested type.
		pubJWK, err := key.PublicKey()
		require.NoError(t, err)

		got, err := jwk.Export[*mldsa.PublicKey](pubJWK)
		require.NoError(t, err)
		require.Equal(t, sk.PublicKey().Bytes(), got.Bytes())
	})

	t.Run("stdlib private", func(t *testing.T) {
		t.Parallel()
		got, err := jwk.Export[*stdmldsa.PrivateKey](key)
		require.NoError(t, err)
		require.Equal(t, sk.Bytes(), got.Bytes())
	})

	t.Run("stdlib public", func(t *testing.T) {
		t.Parallel()
		pubJWK, err := key.PublicKey()
		require.NoError(t, err)

		got, err := jwk.Export[*stdmldsa.PublicKey](pubJWK)
		require.NoError(t, err)
		require.Equal(t, sk.PublicKey().Bytes(), got.Bytes())
	})
}

// Converting a key must not launder an algorithm/key mismatch past the
// parameter-set check.
func TestInteropRejectsParamSetConfusion(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	cases := []struct {
		name     string
		routeAlg jwa.SignatureAlgorithm
		keyGen   *mldsa.Parameters
	}{
		{"ML-DSA-65-as-ML-DSA-44", jwxmldsa.MLDSA44(), mldsa.MLDSA65()},
		{"ML-DSA-44-as-ML-DSA-87", jwxmldsa.MLDSA87(), mldsa.MLDSA44()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			_, err = jws.Sign([]byte("payload"), jws.WithKey(tc.routeAlg, sk))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")

			// And on the verify side, with a signature the key can really make.
			signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.NewSignatureAlgorithm(tc.keyGen.String()), sk))
			require.NoError(t, err)
			_, err = jws.Verify(signed, jws.WithKey(tc.routeAlg, sk.PublicKey()))
			require.Error(t, err)
		})
	}
}

// Conversion must be exact for every parameter set, in both directions.
func TestInteropKeyConversionIsLossless(t *testing.T) {
	requireInterop(t)
	t.Parallel()

	for _, params := range []*mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			stdParams := stdParamsFor(t, params)

			fsk, err := mldsa.GenerateKey(params)
			require.NoError(t, err)

			ssk, err := stdmldsa.NewPrivateKey(stdParams, fsk.Bytes())
			require.NoError(t, err)
			require.Equal(t, fsk.Bytes(), ssk.Bytes())
			require.Equal(t, fsk.PublicKey().Bytes(), ssk.PublicKey().Bytes())

			back, err := mldsa.NewPrivateKey(params, ssk.Bytes())
			require.NoError(t, err)
			require.Equal(t, fsk.Bytes(), back.Bytes())
		})
	}
}
