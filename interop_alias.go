//go:build go1.27 && !fips140v1.0

package mldsa

// registerInterop installs nothing and reports that interop mode is active.
//
// On Go 1.27, filippo.io/mldsa declares its key and parameter types as
// aliases of the crypto/mldsa types (outside the fips140v1.0 tag, which
// interop_bridge.go covers). A filippo key is therefore a crypto/mldsa key,
// and the importers, exporters, signers, and verifiers jwx already registered
// accept it as is. Registering importers for the same types again would fail,
// so there is nothing to add and nothing to convert.
func registerInterop() bool {
	return true
}
