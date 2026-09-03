//go:build !cmfa

package tun

// Standalone mihomo keeps its existing native Darwin TUN behavior.
const platformTunRequiresFileDescriptor = false
