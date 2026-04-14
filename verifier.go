package mldsa

import (
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

type mldsaVerifier struct {
	algName string
	params  *mldsa.Parameters
}

func (v *mldsaVerifier) Verify(key any, payload, signature []byte) error {
	pk, err := extractPublicKey(key, v.params)
	if err != nil {
		return fmt.Errorf(`mldsa.Verify: %w`, err)
	}
	return jwsbb.Verify(pk, v.algName, payload, signature)
}

func extractPublicKey(key any, params *mldsa.Parameters) (*mldsa.PublicKey, error) {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		if err := requireParamsMatch(k.Parameters(), params); err != nil {
			return nil, err
		}
		return k, nil
	case *mldsa.PrivateKey:
		pk := k.PublicKey()
		if err := requireParamsMatch(pk.Parameters(), params); err != nil {
			return nil, err
		}
		return pk, nil
	case jwk.Key:
		if k.KeyType() != jwa.AKP() {
			return nil, fmt.Errorf(`expected AKP key type, got %s`, k.KeyType())
		}

		pubV, ok := k.Field(jwk.AKPPubKey)
		if !ok {
			return nil, fmt.Errorf(`key does not contain "pub" field`)
		}
		pubBytes, ok := pubV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"pub" field is not []byte`)
		}

		pk, err := mldsa.NewPublicKey(params, pubBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA public key: %w`, err)
		}
		return pk, nil
	default:
		return nil, fmt.Errorf(`unsupported key type %T for ML-DSA verification`, key)
	}
}
