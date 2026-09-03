//go:build !darwin

package hako

// The listener scope exists because of the Apple Network Extension's socket
// interface scope; other platforms have nothing to repair.
func installListenerScopeHooks(underNetworkExtension bool) {}
