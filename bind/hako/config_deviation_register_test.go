package hako

import (
	"regexp"
	"testing"
)

// The sentences a reader sees on the deviations page are in the reader's register: what
// happened to them and what they can do. Nothing in them names a file, a function, an API
// type, a kernel constant, a Linux tool, a system call, a device path or a decision number.
// That material is the developer's and lives in source and mechanism, which the clients keep
// for the diagnostics export and never put on screen.
//
// The user's words, on seeing an iOS screen that read "bind/hako/config_pipeline.go:119-124
// (the StoreFakeIPSet guard)": that is Go's decision-making shown to someone who came to change
// a setting. The outward rule is older than this file -- state facts, not mechanism -- and the
// report walked straight into it. This gate is the ruler, so the call is not left to an eye.
var developerRegister = regexp.MustCompile(
	`\.(go|swift)\b` + // source files
		`|\b(?:NE|CF|NS)[A-Z][A-Za-z0-9]+\b|\b(?:TunOptions|FinalizeForIOS|StoreFakeIPSet|DefaultRawConfig)\b` + // Apple API prefixes and this binding\'s own type/function names -- not "CamelCase is red", which would flag Fake-IP, GeoIP, SERVFAIL
		`|\b(?:SOCK_DGRAM|IP_BOUND_IF|SO_MARK|IP_TRANSPARENT|DIOCNATLOOK)\b` + // kernel constants
		`|\b(?:nftables|iptables|iproute2|netfilter|sing-tun|gVisor|bbolt)\b` + // implementation names
		`|\b(?:bind|listener|hub|component|config|adapter)/[a-z_/]+\.go\b` + // repository path shape
		`|\b(?:ioctl|sysctl|settimeofday|readv|writev|recvmsg|sendmsg)\b` + // system calls
		`|\b(?:utun|fd|pcblist)\b` + // kernel-side nouns
		`|/dev/` + // device paths
		`|\bD-\d{3}\b|\bT-[A-Z0-9-]+\b` + // decision / task numbers
		`|\b(?:mihomo|sing-box|Meta|darwin)\b`, // upstream project names: the product is Clash, and the core is "the core" on screen (macOS lane caught twelve of these; their own gate scans only the localisation table and could not see a core-supplied string)
)

func TestUserFacingSentencesCarryNoMechanism(t *testing.T) {
	check := func(where, sentence string) {
		if m := developerRegister.FindAllString(sentence, -1); len(m) > 0 {
			t.Errorf("%s carries developer-register material %v; move it to mechanism/source:\n  %q", where, m, sentence)
		}
	}
	for _, rule := range deviationRules {
		check(rule.field+".effective", rule.effective)
		check(rule.field+".reason", rule.reason)
		check(rule.field+".alternative", rule.alternative)
	}
	// The shared family sentences, once each.
	for name, text := range map[string]string{
		"tunPacketTunnelShape": tunPacketTunnelShape,
		"tunRoutingIsApples":   tunRoutingIsApples,
		"tunOffloadBridge":     tunOffloadBridge,
		"tunBatchIOBridge":     tunBatchIOBridge,
		"tunAutoRouteFilter":   tunAutoRouteFilter,
	} {
		check("family "+name, text)
	}
	// The two synthetic rule-effect entries are literal text in ownerMetadataRuleDeviations;
	// run it on a configuration that produces both and check what comes out.
	box, err := ConfigDeviationsJSON("rules:\n  - PROCESS-NAME,curl,DIRECT\n  - PROCESS-NAME-REGEX,.*,DIRECT\n  - MATCH,DIRECT\nproxies: []\n", RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	check("synthetic rows (whole report)", stripDeveloperOnlyFields(box.Value))
}

// stripDeveloperOnlyFields blanks the source and mechanism values in a report so the register
// check reads only what a client puts on screen.
func stripDeveloperOnlyFields(report string) string {
	for _, key := range []string{`"source":"`, `"mechanism":"`} {
		for {
			i := indexOf(report, key)
			if i < 0 {
				break
			}
			j := i + len(key)
			for j < len(report) && !(report[j] == '"' && report[j-1] != '\\') {
				j++
			}
			report = report[:i] + `"x":"` + report[j:]
		}
	}
	return report
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
