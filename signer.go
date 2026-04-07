package mldsa

import (
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type mldsaSigner struct {
	params *mldsa.Parameters
}

func (s *mldsaSigner) Sign(key any, payload []byte) ([]byte, error) {
	sk, err := extractPrivateKey(key, s.params)
	if err != nil {
		return nil, fmt.Errorf(`mldsa.Sign: %w`, err)
	}
	return sk.Sign(nil, payload, nil)
}

func extractPrivateKey(key any, params *mldsa.Parameters) (*mldsa.PrivateKey, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		return k, nil
	case jwk.Key:
		if k.KeyType() != AKP() {
			return nil, fmt.Errorf(`expected AKP key type, got %s`, k.KeyType())
		}

		privV, ok := k.Field(AKPPrivKey)
		if !ok {
			return nil, fmt.Errorf(`key does not contain "priv" field`)
		}
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"priv" field is not []byte`)
		}

		sk, err := mldsa.NewPrivateKey(params, privBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA private key: %w`, err)
		}
		return sk, nil
	default:
		return nil, fmt.Errorf(`unsupported key type %T for ML-DSA signing`, key)
	}
}
