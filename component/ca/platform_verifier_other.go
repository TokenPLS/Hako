//go:build !darwin

package ca

// Everywhere else crypto/x509 verifies in-process, so there is no XPC cost to avoid and no
// reason to move off the platform trust store. Keeping this a compile-time constant means
// the Apple carve-out cannot be widened by accident.
const platformDelegatesCertificateVerification = false
