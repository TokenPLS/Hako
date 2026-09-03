package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

type rawOutboundDiagnosticsConfig struct {
	Proxies []struct {
		Name   string `yaml:"name"`
		Type   string `yaml:"type"`
		Server string `yaml:"server"`
	} `yaml:"proxies"`
}

// snapshotOutboundEndpointKinds emits only a one-way anonymous node ID and an
// endpoint class. It never retains or reports proxy names, server addresses,
// ports, credentials or protocol options.
func snapshotOutboundEndpointKinds(configContent string) map[string]string {
	var raw rawOutboundDiagnosticsConfig
	if err := yaml.Unmarshal([]byte(configContent), &raw); err != nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(raw.Proxies))
	for _, proxy := range raw.Proxies {
		if proxy.Name == "" || proxy.Type == "" {
			continue
		}
		result[anonymizedNodeID(proxy.Name, proxy.Type)] = endpointKind(proxy.Server)
	}
	return result
}

func anonymizedNodeID(name, protocolType string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(protocolType) + "\x00" + name))
	return hex.EncodeToString(digest[:8])
}

func endpointKind(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return "unknown"
	}
	if address, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		if address.Is4() {
			return "ipv4"
		}
		return "ipv6"
	}
	return "hostname"
}
