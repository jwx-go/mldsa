package mldsa_test

import (
	"encoding/json"
	"testing"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	jwxmldsa "github.com/jwx-go/mldsa/v4"
)

func FuzzSignAndVerifyMLDSA44(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		f.Fatal(err)
	}
	pk := sk.PublicKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA44(), sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), pk))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzSignAndVerifyMLDSA65(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		f.Fatal(err)
	}
	pk := sk.PublicKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), pk))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzSignAndVerifyMLDSA87(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		f.Fatal(err)
	}
	pk := sk.PublicKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA87(), sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA87(), pk))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzJWKRoundTrip(f *testing.F) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		f.Fatal(err)
	}
	jwkKey, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		f.Fatal(err)
	}
	seedJSON, err := json.Marshal(jwkKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))
	f.Add([]byte(`{"kty":"AKP","alg":"ML-DSA-65","pub":"AAAA"}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKeyAs[jwk.Key](buf)
	})
}
