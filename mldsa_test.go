package mldsa_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"testing"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"

	jwxmldsa "github.com/jwx-go/mldsa/v4"
)

func TestAlgorithmConstants(t *testing.T) {
	t.Parallel()

	t.Run("key type", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "AKP", jwa.AKP().String())
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
			require.Equal(t, jwa.AKP(), privJWK.KeyType())

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
	parsed, err := jwk.ParseKeyAs[jwk.Key](serialized)
	require.NoError(t, err)
	require.Equal(t, jwa.AKP(), parsed.KeyType())

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

	parsed, err := jwk.ParseKeyAs[jwk.Key](serialized)
	require.NoError(t, err)
	require.Equal(t, jwa.AKP(), parsed.KeyType())
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
	require.True(t, pubJWK.Has(jwk.AKPPubKey))
	require.False(t, pubJWK.Has(jwk.AKPPrivKey))
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
		data := json.RawMessage(`{"kty":"AKP","pub":"AAAA"}`)
		_, err := jwk.ParseKeyAs[jwk.Key]([]byte(data))
		require.Error(t, err)
	})

	t.Run("missing pub", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"kty":"AKP","alg":"ML-DSA-65"}`)
		_, err := jwk.ParseKeyAs[jwk.Key]([]byte(data))
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

// TestParamSetConfusionAttack pins the EXT-010 key/alg confusion fix.
//
// filippo.io/mldsa binds the parameter set to the key object, so a
// *mldsa.PublicKey from an ML-DSA-65 keypair will happily verify an
// ML-DSA-65 signature even if the caller asked for ML-DSA-44. Without
// an explicit cross-check between the caller-supplied raw key and the
// algorithm's registered parameter set, a peer that trusts the JWS
// protected header for PQ-security-level policy can be misled about
// which parameter set actually signed the payload.
//
// Each subtest exercises one of five attack surfaces by pairing a
// routeAlg (claimed on the wire) with a key generated under a
// different parameter set. All five surfaces must reject with
// "parameter set mismatch".
func TestParamSetConfusionAttack(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		routeAlg jwa.SignatureAlgorithm
		keyGen   *mldsa.Parameters
	}{
		{"ML-DSA-65-as-ML-DSA-44", jwxmldsa.MLDSA44(), mldsa.MLDSA65()},
		{"ML-DSA-87-as-ML-DSA-44", jwxmldsa.MLDSA44(), mldsa.MLDSA87()},
		{"ML-DSA-87-as-ML-DSA-65", jwxmldsa.MLDSA65(), mldsa.MLDSA87()},
		{"ML-DSA-44-as-ML-DSA-65", jwxmldsa.MLDSA65(), mldsa.MLDSA44()},
		{"ML-DSA-44-as-ML-DSA-87", jwxmldsa.MLDSA87(), mldsa.MLDSA44()},
		{"ML-DSA-65-as-ML-DSA-87", jwxmldsa.MLDSA87(), mldsa.MLDSA65()},
	}

	payload := []byte("EXT-010 parameter-set confusion reproducer")

	for _, tc := range cases {
		t.Run("jws.Sign/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			_, err = jws.Sign(payload, jws.WithKey(tc.routeAlg, sk))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jwsbb.Sign/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			_, err = jwsbb.Sign(sk, tc.routeAlg.String(), payload, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jws.Sign/JWK/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)

			_, err = jws.Sign(payload, jws.WithKey(tc.routeAlg, privJWK))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
			require.NotContains(t, err.Error(), "failed to construct ML-DSA private key")
		})

		t.Run("jws.Verify/"+tc.name, func(t *testing.T) {
			t.Parallel()
			// Build a wire-level forgery independently of jws.Sign:
			// hand-craft a compact JWS whose header claims routeAlg
			// but whose signature is a real mldsa.Sign under the
			// wrong parameter set. This guarantees a valid signature
			// reaches the verifier even with the sign-side fix in place.
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			pk := sk.PublicKey()

			forged := forgeCompactJWS(t, sk, tc.routeAlg.String(), payload)

			_, err = jws.Verify(forged, jws.WithKey(tc.routeAlg, pk))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jws.Verify/JWK/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			pubJWK, err := jwk.Import[jwk.Key](sk.PublicKey())
			require.NoError(t, err)

			forged := forgeCompactJWS(t, sk, tc.routeAlg.String(), payload)

			_, err = jws.Verify(forged, jws.WithKey(tc.routeAlg, pubJWK))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
			require.NotContains(t, err.Error(), "failed to construct ML-DSA public key")
		})

		t.Run("jwsbb.Verify/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			pk := sk.PublicKey()

			signingInput := []byte("direct-dsig-" + tc.name)
			sig, err := sk.Sign(nil, signingInput, nil)
			require.NoError(t, err)

			err = jwsbb.Verify(pk, tc.routeAlg.String(), signingInput, sig)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})
	}
}

// forgeCompactJWS constructs a compact JWS by hand, using mldsa.Sign
// directly so the resulting signature is byte-valid under sk's own
// parameter set regardless of what algHeader claims.
func forgeCompactJWS(t *testing.T, sk *mldsa.PrivateKey, algHeader string, payload []byte) []byte {
	t.Helper()

	hdr, err := json.Marshal(map[string]string{"alg": algHeader})
	require.NoError(t, err)

	b64 := base64.RawURLEncoding
	encHdr := b64.EncodeToString(hdr)
	encPayload := b64.EncodeToString(payload)
	signingInput := []byte(encHdr + "." + encPayload)

	sig, err := sk.Sign(nil, signingInput, nil)
	require.NoError(t, err)

	return []byte(encHdr + "." + encPayload + "." + b64.EncodeToString(sig))
}

// TestSignVerifyWithOptsTypeMismatch pins that a non-nil crypto.SignerOpts
// whose concrete type is not *mldsa.Options is rejected instead of silently
// coerced to nil. The silent-coerce behavior would let a caller believe their
// Context field was being honored while the verifier ran with ctx="" —
// a signature-substitution vector for composite signatures (jwx-go/compsig).
func TestSignVerifyWithOptsTypeMismatch(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pk := sk.PublicKey()

	msg := []byte("mldsa opts type mismatch regression")

	t.Run("Sign rejects non-*mldsa.Options opts", func(t *testing.T) {
		t.Parallel()
		_, err := jwsbb.SignWithOpts(sk, "ML-DSA-65", msg, crypto.SHA256, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")
	})

	t.Run("Verify rejects non-*mldsa.Options opts", func(t *testing.T) {
		t.Parallel()
		sig, err := jwsbb.Sign(sk, "ML-DSA-65", msg, nil)
		require.NoError(t, err)

		err = jwsbb.VerifyWithOpts(pk, "ML-DSA-65", msg, sig, crypto.SHA256)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")
	})

	t.Run("Sign/Verify accept nil opts", func(t *testing.T) {
		t.Parallel()
		sig, err := jwsbb.SignWithOpts(sk, "ML-DSA-65", msg, nil, nil)
		require.NoError(t, err)
		require.NoError(t, jwsbb.VerifyWithOpts(pk, "ML-DSA-65", msg, sig, nil))
	})

	t.Run("Sign/Verify honor *mldsa.Options Context", func(t *testing.T) {
		t.Parallel()
		opts := &mldsa.Options{Context: "jwx-test-ctx"}
		sig, err := jwsbb.SignWithOpts(sk, "ML-DSA-65", msg, opts, nil)
		require.NoError(t, err)
		require.NoError(t, jwsbb.VerifyWithOpts(pk, "ML-DSA-65", msg, sig, opts))

		wrong := &mldsa.Options{Context: "different"}
		require.Error(t, jwsbb.VerifyWithOpts(pk, "ML-DSA-65", msg, sig, wrong))
	})
}

// TestJWKAlgValidation pins MLDSA-001: extractPrivateKey /
// extractPublicKey must treat a missing or non-ML-DSA alg on the JWK
// as a hard error rather than skipping the parameter-set check. The
// 32-byte seed is the same length across all three ML-DSA variants,
// so length-based filtering provides zero discrimination — without
// the alg check, an attacker who controls the JWK can have the signer
// produce a signature under a parameter set the JWK never claimed.
func TestJWKAlgValidation(t *testing.T) {
	t.Parallel()

	payload := []byte("alg-validation pin")

	t.Run("Sign rejects JWK with missing alg", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		require.NoError(t, privJWK.Remove(jwk.AlgorithmKey),
			`removing alg from AKP JWK should succeed`)

		_, err = jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), privJWK))
		require.Error(t, err, `Sign should refuse an AKP JWK without alg`)
	})

	t.Run("Verify rejects JWK with missing alg", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), privJWK))
		require.NoError(t, err)

		pubJWK, err := privJWK.PublicKey()
		require.NoError(t, err)
		require.NoError(t, pubJWK.Remove(jwk.AlgorithmKey))

		_, err = jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), pubJWK))
		require.Error(t, err, `Verify should refuse an AKP JWK without alg`)
	})

	t.Run("Sign rejects JWK whose alg is not an ML-DSA variant", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)

		// RS256 is a valid registered alg but not one of the three
		// ML-DSA variants. paramsForAlg returns an error for it,
		// which the buggy extractPrivateKey treats as "no further
		// check needed" instead of "the JWK lied".
		require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.RS256()))

		_, err = jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), privJWK))
		require.Error(t, err, `Sign should refuse an AKP JWK with non-ML-DSA alg`)
	})

	t.Run("Verify rejects JWK whose alg is not an ML-DSA variant", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), privJWK))
		require.NoError(t, err)

		pubJWK, err := privJWK.PublicKey()
		require.NoError(t, err)
		require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.RS256()))

		_, err = jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), pubJWK))
		require.Error(t, err, `Verify should refuse an AKP JWK with non-ML-DSA alg`)
	})
}

// TestJWKSignRejectsPubMismatch pins MLDSA-002: extractPrivateKey
// must reject an AKP JWK whose "pub" field does not match the public
// key derived from "priv". Without this check, the signer happily
// produces a signature under the seed-derived public key, but
// relying parties trusting the JWK's "pub" cannot verify it. The
// exporter at exportMLDSAKey already enforces the comparison; the
// signer path didn't.
func TestJWKSignRejectsPubMismatch(t *testing.T) {
	t.Parallel()

	skA, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	skB, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](skA)
	require.NoError(t, err)

	// Replace pub with a different key's public bytes; the priv field
	// (skA's seed) now no longer derives to the stored pub.
	require.NoError(t, privJWK.Set(jwk.AKPPubKey, skB.PublicKey().Bytes()))

	_, err = jws.Sign([]byte("pub-mismatch pin"), jws.WithKey(jwxmldsa.MLDSA65(), privJWK))
	require.Error(t, err, `Sign should refuse an AKP JWK whose pub does not match priv`)
}
