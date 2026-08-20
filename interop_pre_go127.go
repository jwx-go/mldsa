//go:build !go1.27

package mldsa

// registerInterop installs nothing and reports that interop mode is not
// active. The bridge converts filippo.io/mldsa keys into crypto/mldsa keys,
// and crypto/mldsa does not exist before Go 1.27, so there is nothing to
// convert to and this package stands down completely.
//
// Reaching this at all takes a third party registering ML-DSA with dsig on Go
// 1.26. Neither dsig's implementation nor jwx's is compiled in before Go 1.27,
// so in every ordinary Go 1.26 build the probe in init() misses and this
// package owns ML-DSA outright.
func registerInterop() bool {
	return false
}
