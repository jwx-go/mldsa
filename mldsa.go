// Package mldsa provides ML-DSA (FIPS 204) support for the jwx library.
//
// ML-DSA is a post-quantum digital signature scheme. This module bridges
// filippo.io/mldsa into jwx's algorithm registration system, enabling
// ML-DSA key types and signing/verification in JWK, JWS, and JWT workflows.
//
// Import this package for its side effects to enable ML-DSA support:
//
//	import _ "github.com/jwx-go/mldsa"
//
// This registers the AKP key type, ML-DSA-44/65/87 signature algorithms,
// JWK key parsing/import/export, and JWS signing/verification.
package mldsa

import (
	"encoding/json"
	"fmt"
	"reflect"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const (
	privateKeySize = 32 // ML-DSA seed size for all parameter sets
)

// AKP returns the AKP (Algorithm Key Pair) key type.
func AKP() jwa.KeyType {
	return jwa.NewKeyType("AKP")
}

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

// pubKeySizeForAlg returns the expected public key size for the given algorithm.
func pubKeySizeForAlg(alg string) (int, bool) {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44PublicKeySize, true
	case "ML-DSA-65":
		return mldsa.MLDSA65PublicKeySize, true
	case "ML-DSA-87":
		return mldsa.MLDSA87PublicKeySize, true
	default:
		return 0, false
	}
}

func init() {
	// Register key type
	jwa.RegisterKeyType(AKP())

	// Register signature algorithms
	jwa.RegisterSignatureAlgorithm(MLDSA44(), MLDSA65(), MLDSA87())

	// Register probe field for "priv" to distinguish public/private AKP keys
	if err := jwk.RegisterProbeField(reflect.StructField{
		Name: "AKPPriv",
		Type: reflect.TypeFor[json.RawMessage](),
		Tag:  `json:"priv,omitempty"`,
	}); err != nil {
		panic(fmt.Sprintf("mldsa: failed to register probe field: %s", err))
	}

	// Register key parser
	jwk.RegisterKeyParser(jwk.KeyParseFunc(parseAKPKey))

	// Register key importers for raw mldsa key types
	jwk.RegisterKeyImporter(importMLDSAPrivateKey)
	jwk.RegisterKeyImporter(importMLDSAPublicKey)

	// Register key exporter for AKP keys
	jwk.RegisterKeyExporter(jwk.KeyKind("AKP"), jwk.KeyExportFunc(exportAKPKey))

	// Associate algorithms with the AKP key type
	jws.RegisterAlgorithmForKeyType(AKP(), MLDSA44())
	jws.RegisterAlgorithmForKeyType(AKP(), MLDSA65())
	jws.RegisterAlgorithmForKeyType(AKP(), MLDSA87())

	// Register signers and verifiers
	for _, entry := range []struct {
		alg    jwa.SignatureAlgorithm
		params *mldsa.Parameters
	}{
		{MLDSA44(), mldsa.MLDSA44()},
		{MLDSA65(), mldsa.MLDSA65()},
		{MLDSA87(), mldsa.MLDSA87()},
	} {
		if err := jws.RegisterSigner(entry.alg, &mldsaSigner{params: entry.params}); err != nil {
			panic(fmt.Sprintf("mldsa: failed to register signer for %s: %s", entry.alg, err))
		}
		if err := jws.RegisterVerifier(entry.alg, &mldsaVerifier{params: entry.params}); err != nil {
			panic(fmt.Sprintf("mldsa: failed to register verifier for %s: %s", entry.alg, err))
		}
	}
}

// parseAKPKey is the KeyParser for AKP key type.
func parseAKPKey(probe *jwk.KeyProbe, unmarshaler jwk.KeyUnmarshaler, data []byte) (jwk.Key, error) {
	ktyV, ok := probe.Field("Kty")
	if !ok {
		return nil, jwk.ContinueError()
	}
	kty, ok := ktyV.(string)
	if !ok || kty != "AKP" {
		return nil, jwk.ContinueError()
	}

	// Check if this is a private key by looking for the "priv" field
	privV, _ := probe.Field("AKPPriv")
	priv, _ := privV.(json.RawMessage)

	var key jwk.Key
	if priv != nil {
		key = newAKPPrivateKey()
	} else {
		key = newAKPPublicKey()
	}

	if err := unmarshaler.UnmarshalKey(data, key); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal AKP key: %w`, err)
	}
	return key, nil
}

// importMLDSAPrivateKey converts a *mldsa.PrivateKey to a jwk.Key.
func importMLDSAPrivateKey(raw *mldsa.PrivateKey) (jwk.Key, error) {
	key := newAKPPrivateKey()

	pub := raw.PublicKey()
	params := pub.Parameters()
	alg, err := jwa.KeyAlgorithmFrom(params.String())
	if err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	key.algorithm = &alg
	key.pub = pub.Bytes()
	key.priv = raw.Bytes()

	return key, nil
}

// importMLDSAPublicKey converts a *mldsa.PublicKey to a jwk.Key.
func importMLDSAPublicKey(raw *mldsa.PublicKey) (jwk.Key, error) {
	key := newAKPPublicKey()

	params := raw.Parameters()
	alg, err := jwa.KeyAlgorithmFrom(params.String())
	if err != nil {
		return nil, fmt.Errorf(`mldsa import: %w`, err)
	}
	key.algorithm = &alg
	key.pub = raw.Bytes()

	return key, nil
}

// exportAKPKey converts a jwk.Key to a raw mldsa key type.
func exportAKPKey(key jwk.Key, hint any) (any, error) {
	algV, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`missing "alg" field`)
	}

	params, err := paramsForAlg(algV.String())
	if err != nil {
		return nil, err
	}

	pubV, ok := key.Field(AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	pubBytes, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`"pub" field is not []byte`)
	}

	privV, hasPriv := key.Field(AKPPrivKey)
	if hasPriv {
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"priv" field is not []byte`)
		}

		sk, err := mldsa.NewPrivateKey(params, privBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA private key: %w`, err)
		}

		// Verify that the public key matches
		derivedPub := sk.PublicKey().Bytes()
		if len(derivedPub) != len(pubBytes) {
			return nil, fmt.Errorf(`"pub" does not match derived public key`)
		}
		for i := range derivedPub {
			if derivedPub[i] != pubBytes[i] {
				return nil, fmt.Errorf(`"pub" does not match derived public key`)
			}
		}

		return sk, nil
	}

	pk, err := mldsa.NewPublicKey(params, pubBytes)
	if err != nil {
		return nil, fmt.Errorf(`failed to construct ML-DSA public key: %w`, err)
	}
	return pk, nil
}
