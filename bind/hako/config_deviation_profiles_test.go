package hako

// registryProfiles pairs each profile with the placement it actually runs in: the packet
// tunnels inside the Network Extension, the containing-app profile outside it. Evaluating a
// profile in the wrong placement answers a question no deployment asks.
var registryProfiles = []struct {
	name                  string
	profile               runtimeProfile
	underNetworkExtension bool
}{
	{RuntimeProfileIOSPacketTunnel, runtimeProfileIOSPacketTunnel, true},
	{RuntimeProfileMacOSPacketTunnel, runtimeProfileMacOSPacketTunnel, true},
	{RuntimeProfileTVOSPacketTunnel, runtimeProfileTVOSPacketTunnel, true},
	{RuntimeProfileMacOSApplication, runtimeProfileMacOSApplication, false},
}
