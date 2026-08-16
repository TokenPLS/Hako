package hako

import (
	"reflect"
	"testing"

	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
)

func TestAppleRuntimePolicyMatrix(t *testing.T) {
	tests := []struct {
		name                string
		profile             runtimeProfile
		underNE             bool
		wantNE              bool
		wantPacketTunnel    bool
		wantTrustedProcess  bool
		wantPacketTunnelDNS bool
		wantMemoryGeodata   bool
	}{
		{
			name: "iOS packet tunnel", profile: runtimeProfileIOSPacketTunnel, underNE: true,
			wantNE: true, wantPacketTunnel: true, wantPacketTunnelDNS: true, wantMemoryGeodata: true,
		},
		{
			name: "macOS packet tunnel", profile: runtimeProfileMacOSPacketTunnel, underNE: true,
			wantNE: true, wantPacketTunnel: true, wantPacketTunnelDNS: true,
		},
		{
			name: "macOS application", profile: runtimeProfileMacOSApplication, underNE: false,
			wantTrustedProcess: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := runtimePolicyFor(test.profile, test.underNE)
			if policy.networkExtension != test.wantNE ||
				policy.packetTunnel != test.wantPacketTunnel ||
				policy.trustedProcessMetadata != test.wantTrustedProcess ||
				policy.requirePacketTunnelDNS != test.wantPacketTunnelDNS ||
				policy.memoryConservativeGeodata != test.wantMemoryGeodata {
				t.Fatalf("runtimePolicyFor(%q, %v) = %+v", test.profile, test.underNE, policy)
			}
		})
	}
}

func TestMacOSProfilesPreserveStandardGeodataLoader(t *testing.T) {
	for _, profile := range []runtimeProfile{
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		t.Run(profile.String(), func(t *testing.T) {
			policy := runtimePolicyFor(profile, profile != runtimeProfileMacOSApplication)
			raw := config.DefaultRawConfig()
			raw.GeodataLoader = "standard"
			normalizeRawConfigForApple(raw, policy)
			if raw.GeodataLoader != "standard" {
				t.Fatalf("raw geodata loader = %q, want standard", raw.GeodataLoader)
			}
			cfg := &config.Config{General: &config.General{GeodataLoader: "standard"}}
			overrideForAppleConfig(cfg, policy)
			if cfg.General.GeodataLoader != "standard" {
				t.Fatalf("parsed geodata loader = %q, want standard", cfg.General.GeodataLoader)
			}
		})
	}
}

func TestIOSProfileStillForcesMemoryConservativeGeodataLoader(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	raw := config.DefaultRawConfig()
	raw.GeodataLoader = "standard"
	normalizeRawConfigForApple(raw, policy)
	if raw.GeodataLoader != "memconservative" {
		t.Fatalf("raw iOS geodata loader = %q, want memconservative", raw.GeodataLoader)
	}
	cfg := &config.Config{General: &config.General{GeodataLoader: "standard"}}
	overrideForAppleConfig(cfg, policy)
	if cfg.General.GeodataLoader != "memconservative" {
		t.Fatalf("parsed iOS geodata loader = %q, want memconservative", cfg.General.GeodataLoader)
	}
}

// The ten owner-metadata rule kinds do not share an identity source, so a macOS Packet Tunnel
// must keep some and strip others in the SAME config.
//
// PROCESS-NAME/-PATH and UID all come from one socket-table read: the uid sits at
// xsocket_n.so_uid, the four bytes before the pid this code already read. That uid was returned
// as a hardcoded 0 until it was ported from sing-box, which is why an earlier version of this
// test expected UID to be stripped -- it was unresolvable, not unsupported.
//
// IN-USER stays stripped and always will: it is the user of an INBOUND listener's authentication,
// unrelated to a socket's owner, and every inbound listener is stripped from Apple configurations
// anyway. SOURCE-APP-* stays stripped because it needs an audit token only a flow-level provider
// has.
//
// This test previously asserted that PROCESS-NAME was stripped here too, on the recorded
// grounds that "the NE exposes no process metadata". That reason was wrong twice: mihomo does
// not ask the Network Extension (it reads net.inet.{tcp,udp}.pcblist_n itself), and the App
// Sandbox does not deny those reads -- measured with a binary signed
// com.apple.security.app-sandbox true, the entitlement both macOS shapes carry, with a
// positive control proving the sandbox was engaged. Surge reads the identical two MIB names
// and ships PROCESS-NAME as a headline macOS feature.
func TestMacOSPacketTunnelKeepsEveryOwnerMetadataRule(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-NAME-REGEX,^cur.*,REJECT
  - PROCESS-NAME-WILDCARD,cur*,REJECT
  - PROCESS-PATH,/usr/bin/curl,REJECT
  - PROCESS-PATH-REGEX,^/usr/bin/.*,REJECT
  - PROCESS-PATH-WILDCARD,/usr/bin/*,REJECT
  - UID,501,REJECT
  - IN-USER,alice,REJECT
  - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
  - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
  - MATCH,DIRECT
sub-rules:
  child:
    - PROCESS-NAME,ssh,REJECT
    - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
    - DOMAIN,child.example,DIRECT
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - PROCESS-PATH,/usr/bin/ssh
      - SOURCE-APP-TEAM-ID,ABCDE12345
      - DOMAIN,provider.example
`))
	if err != nil {
		t.Fatal(err)
	}

	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true))

	// Every kind survives in its original order, including IN-USER and SOURCE-APP-*
	// which this profile cannot resolve either: they evaluate against empty metadata
	// and answer false, which is what upstream does when a lookup yields nothing.
	// Removing them used to be justified by "it matches nothing anyway" -- true for a
	// bare rule, false the moment one appears inside a logic rule or a SUB-RULE.
	want := []string{
		"PROCESS-NAME,curl,REJECT",
		"PROCESS-NAME-REGEX,^cur.*,REJECT",
		"PROCESS-NAME-WILDCARD,cur*,REJECT",
		"PROCESS-PATH,/usr/bin/curl,REJECT",
		"PROCESS-PATH-REGEX,^/usr/bin/.*,REJECT",
		"PROCESS-PATH-WILDCARD,/usr/bin/*,REJECT",
		"UID,501,REJECT",
		"IN-USER,alice,REJECT",
		"SOURCE-APP-SIGNING-ID,com.example.cli,REJECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, want) {
		t.Fatalf("macOS Packet Tunnel rules = %v, want %v", raw.Rule, want)
	}
	if want := []string{"PROCESS-NAME,ssh,REJECT", "SOURCE-APP-SIGNING-ID,com.example.cli,REJECT", "DOMAIN,child.example,DIRECT"}; !reflect.DeepEqual(raw.SubRules["child"], want) {
		t.Fatalf("macOS Packet Tunnel sub-rules = %v, want %v", raw.SubRules["child"], want)
	}
	if want := []any{"PROCESS-PATH,/usr/bin/ssh", "SOURCE-APP-TEAM-ID,ABCDE12345", "DOMAIN,provider.example"}; !reflect.DeepEqual(raw.RuleProvider["inline"]["payload"], want) {
		t.Fatalf("macOS Packet Tunnel inline provider = %#v, want %#v", raw.RuleProvider["inline"]["payload"], want)
	}

	// Keeping the rules is useless if the lookup that feeds them is switched off, so the
	// mode must survive too. mihomo's default is Strict: look up only when a rule needs it.
	if raw.FindProcessMode == process.FindProcessOff {
		t.Fatal("find-process-mode was forced off, which makes every PROCESS rule kept above " +
			"match nothing -- the rules and the lookup have to be enabled together")
	}
}

// iOS keeps the old behaviour in full: no flow token, no usable socket table for other
// processes, and process rules are Mac-only upstream too (Surge's manual says iOS ignores
// them). Every kind is stripped and the lookup stays off.
func TestIOSPacketTunnelKeepsEveryMetadataRuleAndForcesLookupOff(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-PATH,/usr/bin/curl,REJECT
  - UID,501,REJECT
  - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
  - MATCH,DIRECT
`))
	if err != nil {
		t.Fatal(err)
	}

	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))

	// The iOS packet tunnel resolves none of these, and still keeps every one. What
	// the profile changes is the lookup, not the rule list -- exactly the shape a
	// mihomo user gets by writing find-process-mode: off.
	// UID is absent: upstream refuses to construct it off linux/android/darwin, so on this
	// profile keeping it would fail the configuration rather than never match.
	want := []string{
		"PROCESS-NAME,curl,REJECT",
		"PROCESS-PATH,/usr/bin/curl,REJECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, want) {
		t.Fatalf("iOS rules = %v, want %v", raw.Rule, want)
	}
	if raw.FindProcessMode != process.FindProcessOff {
		t.Fatalf("iOS find-process-mode = %v, want off: the default is Strict, which would "+
			"attempt a lookup on every connection that cannot succeed", raw.FindProcessMode)
	}
}
