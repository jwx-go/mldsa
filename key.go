package mldsa

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	AKPPubKey  = "pub"
	AKPPrivKey = "priv"
)

// akpPublicKey implements jwk.Key for AKP (Algorithm Key Pair) public keys.
type akpPublicKey struct {
	algorithm              *jwa.KeyAlgorithm
	pub                    []byte
	keyID                  *string
	keyOps                 *jwk.KeyOperationList
	keyUsage               *string
	x509CertChain          *cert.Chain
	x509CertThumbprint     *string
	x509CertThumbprintS256 *string
	x509URL                *string
	privateParams          map[string]any
	mu                     sync.RWMutex
}

var _ jwk.Key = &akpPublicKey{}

func newAKPPublicKey() *akpPublicKey {
	return &akpPublicKey{
		privateParams: make(map[string]any),
	}
}

func (k *akpPublicKey) KeyType() jwa.KeyType { return AKP() }
func (k *akpPublicKey) IsPrivate() bool       { return false }

func (k *akpPublicKey) KeyKind() jwk.KeyKind {
	return jwk.KeyKind("AKP")
}

func (k *akpPublicKey) Pub() ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.pub != nil {
		return k.pub, true
	}
	return nil, false
}

func (k *akpPublicKey) Algorithm() (jwa.KeyAlgorithm, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.algorithm != nil {
		return *k.algorithm, true
	}
	return nil, false
}

func (k *akpPublicKey) KeyID() (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.keyID != nil {
		return *k.keyID, true
	}
	return "", false
}

func (k *akpPublicKey) KeyOps() (jwk.KeyOperationList, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.keyOps != nil {
		return *k.keyOps, true
	}
	return nil, false
}

func (k *akpPublicKey) KeyUsage() (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.keyUsage != nil {
		return *k.keyUsage, true
	}
	return "", false
}

func (k *akpPublicKey) X509CertChain() (*cert.Chain, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.x509CertChain != nil {
		return k.x509CertChain, true
	}
	return nil, false
}

func (k *akpPublicKey) X509CertThumbprint() (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.x509CertThumbprint != nil {
		return *k.x509CertThumbprint, true
	}
	return "", false
}

func (k *akpPublicKey) X509CertThumbprintS256() (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.x509CertThumbprintS256 != nil {
		return *k.x509CertThumbprintS256, true
	}
	return "", false
}

func (k *akpPublicKey) X509URL() (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.x509URL != nil {
		return *k.x509URL, true
	}
	return "", false
}

func (k *akpPublicKey) Has(name string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	switch name {
	case jwk.KeyTypeKey:
		return true
	case jwk.AlgorithmKey:
		return k.algorithm != nil
	case AKPPubKey:
		return k.pub != nil
	case jwk.KeyIDKey:
		return k.keyID != nil
	case jwk.KeyOpsKey:
		return k.keyOps != nil
	case jwk.KeyUsageKey:
		return k.keyUsage != nil
	case jwk.X509CertChainKey:
		return k.x509CertChain != nil
	case jwk.X509CertThumbprintKey:
		return k.x509CertThumbprint != nil
	case jwk.X509CertThumbprintS256Key:
		return k.x509CertThumbprintS256 != nil
	case jwk.X509URLKey:
		return k.x509URL != nil
	default:
		_, ok := k.privateParams[name]
		return ok
	}
}

func (k *akpPublicKey) Field(name string) (any, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	switch name {
	case jwk.KeyTypeKey:
		return k.KeyType(), true
	case jwk.AlgorithmKey:
		if k.algorithm == nil {
			return nil, false
		}
		return *k.algorithm, true
	case AKPPubKey:
		if k.pub == nil {
			return nil, false
		}
		return k.pub, true
	case jwk.KeyIDKey:
		if k.keyID == nil {
			return nil, false
		}
		return *k.keyID, true
	case jwk.KeyOpsKey:
		if k.keyOps == nil {
			return nil, false
		}
		return *k.keyOps, true
	case jwk.KeyUsageKey:
		if k.keyUsage == nil {
			return nil, false
		}
		return *k.keyUsage, true
	case jwk.X509CertChainKey:
		if k.x509CertChain == nil {
			return nil, false
		}
		return k.x509CertChain, true
	case jwk.X509CertThumbprintKey:
		if k.x509CertThumbprint == nil {
			return nil, false
		}
		return *k.x509CertThumbprint, true
	case jwk.X509CertThumbprintS256Key:
		if k.x509CertThumbprintS256 == nil {
			return nil, false
		}
		return *k.x509CertThumbprintS256, true
	case jwk.X509URLKey:
		if k.x509URL == nil {
			return nil, false
		}
		return *k.x509URL, true
	default:
		v, ok := k.privateParams[name]
		return v, ok
	}
}

func (k *akpPublicKey) Set(name string, value any) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.setNoLock(name, value)
}

func (k *akpPublicKey) setNoLock(name string, value any) error {
	switch name {
	case jwk.KeyTypeKey:
		return nil
	case jwk.AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.KeyEncryptionAlgorithm, jwa.ContentEncryptionAlgorithm:
			tmp, err := jwa.KeyAlgorithmFrom(v)
			if err != nil {
				return fmt.Errorf(`invalid value for %s key: %w`, jwk.AlgorithmKey, err)
			}
			k.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %s key: %T`, jwk.AlgorithmKey, value)
		}
		return nil
	case AKPPubKey:
		if v, ok := value.([]byte); ok {
			if v == nil {
				k.pub = nil
			} else {
				k.pub = make([]byte, len(v))
				copy(k.pub, v)
			}
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, AKPPubKey, value)
	case jwk.KeyIDKey:
		if v, ok := value.(string); ok {
			k.keyID = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, jwk.KeyIDKey, value)
	case jwk.KeyOpsKey:
		var acceptor jwk.KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, jwk.KeyOpsKey, err)
		}
		k.keyOps = &acceptor
		return nil
	case jwk.KeyUsageKey:
		switch v := value.(type) {
		case jwk.KeyUsageType:
			tmp := string(v)
			k.keyUsage = &tmp
		case string:
			k.keyUsage = &v
		default:
			return fmt.Errorf(`invalid value for %s key: %T`, jwk.KeyUsageKey, value)
		}
		return nil
	case jwk.X509CertChainKey:
		if v, ok := value.(*cert.Chain); ok {
			k.x509CertChain = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, jwk.X509CertChainKey, value)
	case jwk.X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			k.x509CertThumbprint = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, jwk.X509CertThumbprintKey, value)
	case jwk.X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			k.x509CertThumbprintS256 = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, jwk.X509CertThumbprintS256Key, value)
	case jwk.X509URLKey:
		if v, ok := value.(string); ok {
			k.x509URL = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, jwk.X509URLKey, value)
	default:
		if k.privateParams == nil {
			k.privateParams = map[string]any{}
		}
		k.privateParams[name] = value
		return nil
	}
}

func (k *akpPublicKey) Remove(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch name {
	case jwk.KeyTypeKey:
		return fmt.Errorf(`cannot remove kty`)
	case jwk.AlgorithmKey:
		k.algorithm = nil
	case AKPPubKey:
		k.pub = nil
	case jwk.KeyIDKey:
		k.keyID = nil
	case jwk.KeyOpsKey:
		k.keyOps = nil
	case jwk.KeyUsageKey:
		k.keyUsage = nil
	case jwk.X509CertChainKey:
		k.x509CertChain = nil
	case jwk.X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case jwk.X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case jwk.X509URLKey:
		k.x509URL = nil
	default:
		delete(k.privateParams, name)
	}
	return nil
}

func (k *akpPublicKey) Keys() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	keys := make([]string, 0, 10+len(k.privateParams))
	keys = append(keys, jwk.KeyTypeKey)
	if k.algorithm != nil {
		keys = append(keys, jwk.AlgorithmKey)
	}
	if k.pub != nil {
		keys = append(keys, AKPPubKey)
	}
	if k.keyID != nil {
		keys = append(keys, jwk.KeyIDKey)
	}
	if k.keyOps != nil {
		keys = append(keys, jwk.KeyOpsKey)
	}
	if k.keyUsage != nil {
		keys = append(keys, jwk.KeyUsageKey)
	}
	if k.x509CertChain != nil {
		keys = append(keys, jwk.X509CertChainKey)
	}
	if k.x509CertThumbprint != nil {
		keys = append(keys, jwk.X509CertThumbprintKey)
	}
	if k.x509CertThumbprintS256 != nil {
		keys = append(keys, jwk.X509CertThumbprintS256Key)
	}
	if k.x509URL != nil {
		keys = append(keys, jwk.X509URLKey)
	}
	for name := range k.privateParams {
		keys = append(keys, name)
	}
	return keys
}

func (dst *akpPublicKey) cloneFrom(src *akpPublicKey) {
	src.mu.RLock()
	defer src.mu.RUnlock()
	dst.mu.Lock()
	defer dst.mu.Unlock()

	if src.algorithm != nil {
		tmp := *src.algorithm
		dst.algorithm = &tmp
	} else {
		dst.algorithm = nil
	}
	if src.pub != nil {
		dst.pub = slices.Clone(src.pub)
	} else {
		dst.pub = nil
	}
	if src.keyID != nil {
		tmp := *src.keyID
		dst.keyID = &tmp
	} else {
		dst.keyID = nil
	}
	if src.keyOps != nil {
		tmp := slices.Clone(*src.keyOps)
		dst.keyOps = &tmp
	} else {
		dst.keyOps = nil
	}
	if src.keyUsage != nil {
		tmp := *src.keyUsage
		dst.keyUsage = &tmp
	} else {
		dst.keyUsage = nil
	}
	if src.x509CertChain != nil {
		dst.x509CertChain = src.x509CertChain
	} else {
		dst.x509CertChain = nil
	}
	if src.x509CertThumbprint != nil {
		tmp := *src.x509CertThumbprint
		dst.x509CertThumbprint = &tmp
	} else {
		dst.x509CertThumbprint = nil
	}
	if src.x509CertThumbprintS256 != nil {
		tmp := *src.x509CertThumbprintS256
		dst.x509CertThumbprintS256 = &tmp
	} else {
		dst.x509CertThumbprintS256 = nil
	}
	if src.x509URL != nil {
		tmp := *src.x509URL
		dst.x509URL = &tmp
	} else {
		dst.x509URL = nil
	}
	if len(src.privateParams) > 0 {
		dst.privateParams = make(map[string]any, len(src.privateParams))
		for name, v := range src.privateParams {
			dst.privateParams[name] = v
		}
	} else {
		dst.privateParams = make(map[string]any)
	}
}

func (k *akpPublicKey) Clone() (jwk.Key, error) {
	dst := newAKPPublicKey()
	dst.cloneFrom(k)
	return dst, nil
}

func (k *akpPublicKey) PublicKey() (jwk.Key, error) {
	return k.Clone()
}

func akpThumbprint(hash crypto.Hash, alg, pub string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"alg":"`)
	fmt.Fprint(h, alg)
	fmt.Fprint(h, `","kty":"AKP","pub":"`)
	fmt.Fprint(h, pub)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

func (k *akpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.algorithm == nil {
		return nil, fmt.Errorf(`missing "alg" field`)
	}
	if k.pub == nil {
		return nil, fmt.Errorf(`missing "pub" field`)
	}

	return akpThumbprint(
		hash,
		(*k.algorithm).String(),
		base64.RawURLEncoding.EncodeToString(k.pub),
	), nil
}

func (k *akpPublicKey) Validate() error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.algorithm == nil {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPublicKey: missing required "alg" field`))
	}
	if k.pub == nil {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPublicKey: missing required "pub" field`))
	}

	algStr := (*k.algorithm).String()
	expectedSize, ok := pubKeySizeForAlg(algStr)
	if !ok {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPublicKey: unknown algorithm %q`, algStr))
	}
	if len(k.pub) != expectedSize {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPublicKey: "pub" size %d does not match expected %d for %s`, len(k.pub), expectedSize, algStr))
	}

	return nil
}

func (k *akpPublicKey) MarshalJSON() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	m := make(map[string]any)
	m[jwk.KeyTypeKey] = "AKP"

	if k.algorithm != nil {
		m[jwk.AlgorithmKey] = (*k.algorithm).String()
	}
	if k.pub != nil {
		m[AKPPubKey] = base64.RawURLEncoding.EncodeToString(k.pub)
	}
	if k.keyID != nil {
		m[jwk.KeyIDKey] = *k.keyID
	}
	if k.keyOps != nil {
		m[jwk.KeyOpsKey] = *k.keyOps
	}
	if k.keyUsage != nil {
		m[jwk.KeyUsageKey] = *k.keyUsage
	}
	if k.x509CertChain != nil {
		m[jwk.X509CertChainKey] = k.x509CertChain
	}
	if k.x509CertThumbprint != nil {
		m[jwk.X509CertThumbprintKey] = *k.x509CertThumbprint
	}
	if k.x509CertThumbprintS256 != nil {
		m[jwk.X509CertThumbprintS256Key] = *k.x509CertThumbprintS256
	}
	if k.x509URL != nil {
		m[jwk.X509URLKey] = *k.x509URL
	}
	for name, v := range k.privateParams {
		m[name] = v
	}

	return json.Marshal(m)
}

func (k *akpPublicKey) UnmarshalJSON(data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf(`failed to unmarshal AKP key: %w`, err)
	}

	// Reset all fields
	k.algorithm = nil
	k.pub = nil
	k.keyID = nil
	k.keyOps = nil
	k.keyUsage = nil
	k.x509CertChain = nil
	k.x509CertThumbprint = nil
	k.x509CertThumbprintS256 = nil
	k.x509URL = nil
	k.privateParams = make(map[string]any)

	for name, raw := range m {
		switch name {
		case jwk.KeyTypeKey:
			// validated by parser
		case jwk.AlgorithmKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.AlgorithmKey, err)
			}
			alg, err := jwa.KeyAlgorithmFrom(s)
			if err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.AlgorithmKey, err)
			}
			k.algorithm = &alg
		case AKPPubKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, AKPPubKey, err)
			}
			decoded, err := base64.RawURLEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf(`failed to base64-decode %s: %w`, AKPPubKey, err)
			}
			k.pub = decoded
		case AKPPrivKey:
			// ignore priv in public key
		case jwk.KeyIDKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.KeyIDKey, err)
			}
			k.keyID = &s
		case jwk.KeyOpsKey:
			var ops jwk.KeyOperationList
			if err := json.Unmarshal(raw, &ops); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.KeyOpsKey, err)
			}
			k.keyOps = &ops
		case jwk.KeyUsageKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.KeyUsageKey, err)
			}
			k.keyUsage = &s
		case jwk.X509CertChainKey:
			var chain cert.Chain
			if err := json.Unmarshal(raw, &chain); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.X509CertChainKey, err)
			}
			k.x509CertChain = &chain
		case jwk.X509CertThumbprintKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.X509CertThumbprintKey, err)
			}
			k.x509CertThumbprint = &s
		case jwk.X509CertThumbprintS256Key:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.X509CertThumbprintS256Key, err)
			}
			k.x509CertThumbprintS256 = &s
		case jwk.X509URLKey:
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf(`failed to decode %s: %w`, jwk.X509URLKey, err)
			}
			k.x509URL = &s
		default:
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf(`failed to decode field %s: %w`, name, err)
			}
			k.privateParams[name] = v
		}
	}

	if k.algorithm == nil {
		return fmt.Errorf(`required field "alg" is missing`)
	}
	if k.pub == nil {
		return fmt.Errorf(`required field "pub" is missing`)
	}

	return nil
}

// akpPrivateKey implements jwk.Key for AKP private keys.
type akpPrivateKey struct {
	akpPublicKey
	priv []byte
}

var _ jwk.Key = &akpPrivateKey{}

func newAKPPrivateKey() *akpPrivateKey {
	return &akpPrivateKey{
		akpPublicKey: akpPublicKey{
			privateParams: make(map[string]any),
		},
	}
}

func (k *akpPrivateKey) IsPrivate() bool { return true }

func (k *akpPrivateKey) Priv() ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.priv != nil {
		return k.priv, true
	}
	return nil, false
}

func (k *akpPrivateKey) Has(name string) bool {
	if name == AKPPrivKey {
		k.mu.RLock()
		defer k.mu.RUnlock()
		return k.priv != nil
	}
	return k.akpPublicKey.Has(name)
}

func (k *akpPrivateKey) Field(name string) (any, bool) {
	if name == AKPPrivKey {
		k.mu.RLock()
		defer k.mu.RUnlock()
		if k.priv == nil {
			return nil, false
		}
		return k.priv, true
	}
	return k.akpPublicKey.Field(name)
}

func (k *akpPrivateKey) Set(name string, value any) error {
	if name == AKPPrivKey {
		k.mu.Lock()
		defer k.mu.Unlock()
		if v, ok := value.([]byte); ok {
			if v == nil {
				k.priv = nil
			} else {
				k.priv = make([]byte, len(v))
				copy(k.priv, v)
			}
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, AKPPrivKey, value)
	}
	return k.akpPublicKey.Set(name, value)
}

func (k *akpPrivateKey) Remove(name string) error {
	if name == AKPPrivKey {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.priv = nil
		return nil
	}
	return k.akpPublicKey.Remove(name)
}

func (k *akpPrivateKey) Keys() []string {
	keys := k.akpPublicKey.Keys()
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.priv != nil {
		keys = append(keys, AKPPrivKey)
	}
	return keys
}

func (k *akpPrivateKey) Clone() (jwk.Key, error) {
	dst := newAKPPrivateKey()
	dst.akpPublicKey.cloneFrom(&k.akpPublicKey)

	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.priv != nil {
		dst.priv = slices.Clone(k.priv)
	}
	return dst, nil
}

func (k *akpPrivateKey) PublicKey() (jwk.Key, error) {
	dst := newAKPPublicKey()
	dst.cloneFrom(&k.akpPublicKey)
	return dst, nil
}

func (k *akpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	return k.akpPublicKey.Thumbprint(hash)
}

func (k *akpPrivateKey) Validate() error {
	if err := k.akpPublicKey.Validate(); err != nil {
		return err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.priv == nil {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPrivateKey: missing required "priv" field`))
	}
	if len(k.priv) != privateKeySize {
		return jwk.NewKeyValidationError(fmt.Errorf(`AKPPrivateKey: "priv" size %d does not match expected %d`, len(k.priv), privateKeySize))
	}

	return nil
}

func (k *akpPrivateKey) MarshalJSON() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	m := make(map[string]any)
	m[jwk.KeyTypeKey] = "AKP"

	if k.algorithm != nil {
		m[jwk.AlgorithmKey] = (*k.algorithm).String()
	}
	if k.pub != nil {
		m[AKPPubKey] = base64.RawURLEncoding.EncodeToString(k.pub)
	}
	if k.priv != nil {
		m[AKPPrivKey] = base64.RawURLEncoding.EncodeToString(k.priv)
	}
	if k.keyID != nil {
		m[jwk.KeyIDKey] = *k.keyID
	}
	if k.keyOps != nil {
		m[jwk.KeyOpsKey] = *k.keyOps
	}
	if k.keyUsage != nil {
		m[jwk.KeyUsageKey] = *k.keyUsage
	}
	if k.x509CertChain != nil {
		m[jwk.X509CertChainKey] = k.x509CertChain
	}
	if k.x509CertThumbprint != nil {
		m[jwk.X509CertThumbprintKey] = *k.x509CertThumbprint
	}
	if k.x509CertThumbprintS256 != nil {
		m[jwk.X509CertThumbprintS256Key] = *k.x509CertThumbprintS256
	}
	if k.x509URL != nil {
		m[jwk.X509URLKey] = *k.x509URL
	}
	for name, v := range k.privateParams {
		m[name] = v
	}

	return json.Marshal(m)
}

func (k *akpPrivateKey) UnmarshalJSON(data []byte) error {
	// First unmarshal the public key fields
	if err := k.akpPublicKey.UnmarshalJSON(data); err != nil {
		return err
	}

	// Then extract the priv field
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf(`failed to unmarshal AKP private key: %w`, err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.priv = nil

	if raw, ok := m[AKPPrivKey]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf(`failed to decode %s: %w`, AKPPrivKey, err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf(`failed to base64-decode %s: %w`, AKPPrivKey, err)
		}
		k.priv = decoded
	}

	return nil
}
