package hako

import (
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/config"
)

// Two entries were registered on 2026-08-27 with the honest label "unverified"
// or "reachability-unknown". A label like that is a promise to go and measure,
// not a place to leave something. These are the measurements.

// ConfigPipeline.providerHealthCheckInterval was kept while its sibling,
// health-check.timeout, was released -- on the ground that upstream accepting a
// value at parse says nothing about what its ticker does with it. Now measured,
// and it is the same shape as the proxy-group regex: upstream accepts the
// document and dies later.
//
//	interval: -1
//	  -> adapter/provider/parser.go:69   uint(-1) = 18446744073709551615
//	  -> healthcheck.go:243              time.Duration(that) * time.Second overflows to -1s
//	  -> healthcheck.go:47               time.NewTicker(-1s) panics
//
// Inside a packet-tunnel extension that panic is not a failed health check, it
// is the extension dying and the user's network going with it. Refusing a value
// upstream crashes on is not being stricter than upstream; there is no upstream
// behaviour to be stricter than.
func TestNegativeHealthCheckIntervalWouldPanicUpstream(t *testing.T) {
	negative := -1
	converted := time.Duration(uint(negative)) * time.Second
	if converted > 0 {
		t.Fatalf("the conversion no longer produces a non-positive duration (%v); the refusal's ground "+
			"has moved and needs re-deciding rather than re-asserting", converted)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("time.NewTicker no longer panics on a non-positive interval. The refusal was kept " +
					"because a panic in the extension takes the tunnel down; if that is no longer true, ask " +
					"again whether refusing is right.")
			}
		}()
		ticker := time.NewTicker(converted)
		ticker.Stop()
	}()

	// And mihomo accepts the document, which is why the plan has to be the one
	// to catch it.
	y := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-providers:\n  p:\n    type: inline\n    payload:\n" +
		"      - {name: m, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"    health-check: {enable: true, url: \"http://e.com\", interval: -1}\n"
	if err := mihomoVerdict(t, y); err != nil {
		t.Fatalf("mihomo now refuses this at parse, so this tree no longer needs to: %v", err)
	}
	setupConfigPipelineTest(t)
	if _, err := parseConfigForIOS(y, true); err == nil {
		t.Fatal("a health-check interval that panics the ticker reached the core")
	}
}

// Validate.dnsNameserverRequired was registered as reachability-unknown:
// upstream accepts a dns section with no nameserver, and this tree's own repair
// refills it before validation, which SHOULD make the refusal unreachable.
// "Should" was doing the work. This drives every runtime profile, in and out of
// the extension, and asks whether any of them can reach it.
func TestNoRuntimeProfileReachesTheNameserverRefusal(t *testing.T) {
	document := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n"

	reached := []string{}
	for _, profile := range allRuntimeProfiles() {
		for _, underNE := range []bool{true, false} {
			raw, err := config.UnmarshalRawConfig([]byte(document))
			if err != nil {
				t.Fatalf("fixture does not parse: %v", err)
			}
			policy := runtimePolicyFor(profile, underNE)
			normalizeRawConfigForApple(raw, policy)
			cfg, err := config.ParseRawConfig(raw)
			if err != nil {
				t.Fatalf("%s underNE=%v: the normalized document does not parse: %v", profile, underNE, err)
			}
			if err := validateForApple(cfg, raw, policy); err != nil &&
				strings.Contains(err.Error(), "dns.nameserver must be set explicitly") {
				reached = append(reached, profile.String())
			}
		}
	}
	if len(reached) != 0 {
		t.Fatalf("these profiles reach the nameserver refusal: %v -- the registry records it as "+
			"reachability-unknown, and it is now known. A path that reaches it needs the repair, "+
			"not the refusal.", reached)
	}
}
