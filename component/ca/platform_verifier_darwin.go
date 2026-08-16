//go:build darwin

package ca

// Apple platforms delegate certificate verification to trustd over XPC; see fix_apple.go.
const platformDelegatesCertificateVerification = true
