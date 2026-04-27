package mldsa

import (
	"bytes"
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

type mldsaSigner struct {
	algName string
	params  *mldsa.Parameters
}

func (s *mldsaSigner) Sign(key any, payload []byte) ([]byte, error) {
	sk, err := extractPrivateKey(key, s.params)
	if err != nil {
		return nil, fmt.Errorf(`mldsa.Sign: %w`, err)
	}
	return jwsbb.Sign(sk, s.algName, payload, nil)
}

func extractPrivateKey(key any, params *mldsa.Parameters) (*mldsa.PrivateKey, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		if err := requireParamsMatch(k.PublicKey().Parameters(), params); err != nil {
			return nil, err
		}
		return k, nil
	case jwk.Key:
		if k.KeyType() != jwa.AKP() {
			return nil, fmt.Errorf(`expected AKP key type, got %s`, k.KeyType())
		}
		alg, ok := k.Algorithm()
		if !ok {
			return nil, fmt.Errorf(`AKP key is missing required "alg" field`)
		}
		keyParams, err := paramsForAlg(alg.String())
		if err != nil {
			return nil, fmt.Errorf(`AKP key "alg" is not an ML-DSA variant: %w`, err)
		}
		if err := requireParamsMatch(keyParams, params); err != nil {
			return nil, err
		}

		privV, ok := k.Field(jwk.AKPPrivKey)
		if !ok {
			return nil, fmt.Errorf(`key does not contain "priv" field`)
		}
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"priv" field is not []byte`)
		}

		pubV, ok := k.Field(jwk.AKPPubKey)
		if !ok {
			return nil, fmt.Errorf(`key does not contain "pub" field`)
		}
		pubBytes, ok := pubV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"pub" field is not []byte`)
		}

		sk, err := mldsa.NewPrivateKey(params, privBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA private key: %w`, err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), pubBytes) {
			return nil, fmt.Errorf(`AKP key "pub" does not match the public key derived from "priv"`)
		}
		return sk, nil
	default:
		return nil, fmt.Errorf(`unsupported key type %T for ML-DSA signing`, key)
	}
}
