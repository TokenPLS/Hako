//go:build cmfa && darwin

package tun

import "testing"

func TestCMFARequiresPlatformProvidedTunDescriptor(t *testing.T) {
	if !platformTunRequiresFileDescriptor {
		t.Fatal("cmfa must require a platform-provided descriptor and skip native TUN/DNS helpers")
	}
}
