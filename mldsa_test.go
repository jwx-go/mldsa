package mldsa_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	jwxmldsa "github.com/jwx-go/mldsa"
)

func TestAlgorithmConstants(t *testing.T) {
	t.Parallel()

	t.Run("key type", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "AKP", jwxmldsa.AKP().String())
	})

	t.Run("signature algorithms", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ML-DSA-44", jwxmldsa.MLDSA44().String())
		require.Equal(t, "ML-DSA-65", jwxmldsa.MLDSA65().String())
		require.Equal(t, "ML-DSA-87", jwxmldsa.MLDSA87().String())
	})

	t.Run("lookup registered algorithms", func(t *testing.T) {
		t.Parallel()
		_, ok := jwa.LookupSignatureAlgorithm("ML-DSA-44")
		require.True(t, ok)
		_, ok = jwa.LookupSignatureAlgorithm("ML-DSA-65")
		require.True(t, ok)
		_, ok = jwa.LookupSignatureAlgorithm("ML-DSA-87")
		require.True(t, ok)
	})

	t.Run("unmarshal signature algorithm", func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		require.NoError(t, json.Unmarshal([]byte(`"ML-DSA-65"`), &dst))
		require.Equal(t, jwxmldsa.MLDSA65(), dst)
	})
}

func TestSignVerifyRaw(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		alg    jwa.SignatureAlgorithm
		params *mldsa.Parameters
	}{
		{"ML-DSA-44", jwxmldsa.MLDSA44(), mldsa.MLDSA44()},
		{"ML-DSA-65", jwxmldsa.MLDSA65(), mldsa.MLDSA65()},
		{"ML-DSA-87", jwxmldsa.MLDSA87(), mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := []byte("Hello, post-quantum world!")

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			signed, err := jws.Sign(payload, jws.WithKey(tc.alg, sk))
			require.NoError(t, err)

			// Verify with raw public key
			pk := sk.PublicKey()
			verified, err := jws.Verify(signed, jws.WithKey(tc.alg, pk))
			require.NoError(t, err)
			require.Equal(t, payload, verified)

			// Verify with raw private key (extracts public key internally)
			verified, err = jws.Verify(signed, jws.WithKey(tc.alg, sk))
			require.NoError(t, err)
			require.Equal(t, payload, verified)
		})
	}
}

func TestSignVerifyJWK(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		alg    jwa.SignatureAlgorithm
		params *mldsa.Parameters
	}{
		{"ML-DSA-44", jwxmldsa.MLDSA44(), mldsa.MLDSA44()},
		{"ML-DSA-65", jwxmldsa.MLDSA65(), mldsa.MLDSA65()},
		{"ML-DSA-87", jwxmldsa.MLDSA87(), mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := []byte("Hello, post-quantum world!")

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			// Import to JWK
			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)
			require.Equal(t, jwxmldsa.AKP(), privJWK.KeyType())

			// Sign with JWK private key
			signed, err := jws.Sign(payload, jws.WithKey(tc.alg, privJWK))
			require.NoError(t, err)

			// Verify with JWK public key
			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err)

			verified, err := jws.Verify(signed, jws.WithKey(tc.alg, pubJWK))
			require.NoError(t, err)
			require.Equal(t, payload, verified)
		})
	}
}

func TestJWKParseSerialization(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)

	// Serialize to JSON
	serialized, err := json.Marshal(privJWK)
	require.NoError(t, err)

	// Verify kty and alg are present
	var m map[string]any
	require.NoError(t, json.Unmarshal(serialized, &m))
	require.Equal(t, "AKP", m["kty"])
	require.Equal(t, "ML-DSA-65", m["alg"])
	require.Contains(t, m, "pub")
	require.Contains(t, m, "priv")

	// Parse back
	parsed, err := jwk.ParseKey[jwk.Key](serialized)
	require.NoError(t, err)
	require.Equal(t, jwxmldsa.AKP(), parsed.KeyType())

	alg, ok := parsed.Algorithm()
	require.True(t, ok)
	require.Equal(t, "ML-DSA-65", alg.String())

	// Sign with parsed key, verify with original
	payload := []byte("round-trip test")
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), parsed))
	require.NoError(t, err)

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), sk.PublicKey()))
	require.NoError(t, err)
	require.Equal(t, payload, verified)
}

func TestJWKParsePublicKey(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	pubJWK, err := jwk.Import[jwk.Key](sk.PublicKey())
	require.NoError(t, err)

	serialized, err := json.Marshal(pubJWK)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(serialized, &m))
	require.Equal(t, "AKP", m["kty"])
	require.NotContains(t, m, "priv")

	parsed, err := jwk.ParseKey[jwk.Key](serialized)
	require.NoError(t, err)
	require.Equal(t, jwxmldsa.AKP(), parsed.KeyType())
	require.False(t, parsed.(jwk.AsymmetricKey).IsPrivate())
}

func TestKeyImportExport(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		params *mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			// Import private key
			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)

			// Export private key
			exported, err := jwk.Export[any](privJWK)
			require.NoError(t, err)
			exportedSK, ok := exported.(*mldsa.PrivateKey)
			require.True(t, ok)
			require.True(t, sk.Equal(exportedSK))

			// Import public key
			pk := sk.PublicKey()
			pubJWK, err := jwk.Import[jwk.Key](pk)
			require.NoError(t, err)

			// Export public key
			exported, err = jwk.Export[any](pubJWK)
			require.NoError(t, err)
			exportedPK, ok := exported.(*mldsa.PublicKey)
			require.True(t, ok)
			require.True(t, pk.Equal(exportedPK))
		})
	}
}

func TestThumbprint(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)

	// Private and public keys should produce the same thumbprint
	privTP, err := privJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	pubTP, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, privTP, pubTP)
}

func TestPublicKey(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)
	require.True(t, privJWK.(jwk.AsymmetricKey).IsPrivate())

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)
	require.False(t, pubJWK.(jwk.AsymmetricKey).IsPrivate())
	require.True(t, pubJWK.Has(jwxmldsa.AKPPubKey))
	require.False(t, pubJWK.Has(jwxmldsa.AKPPrivKey))
}

func TestValidate(t *testing.T) {
	t.Parallel()

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()
		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		require.NoError(t, privJWK.Validate())
	})

	t.Run("missing alg", func(t *testing.T) {
		t.Parallel()
		key := json.RawMessage(`{"kty":"AKP","pub":"AAAA"}`)
		_, err := jwk.ParseKey[jwk.Key]([]byte(key))
		require.Error(t, err)
	})

	t.Run("missing pub", func(t *testing.T) {
		t.Parallel()
		key := json.RawMessage(`{"kty":"AKP","alg":"ML-DSA-65"}`)
		_, err := jwk.ParseKey[jwk.Key]([]byte(key))
		require.Error(t, err)
	})
}

func TestCrossAlgorithmRejection(t *testing.T) {
	t.Parallel()

	payload := []byte("cross-algorithm test")

	sk44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	// Sign with ML-DSA-44
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA44(), sk44))
	require.NoError(t, err)

	// Try to verify with ML-DSA-65 key — should fail
	sk65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	_, err = jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), sk65.PublicKey()))
	require.Error(t, err)
}
