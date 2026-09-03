package hako

import (
	"os"
	"testing"
	"time"
)

// Does a configuration this tree accepts actually START?
//
// Every other gate here asks a judgement -- does the plan refuse, does
// FinalizeForIOS accept, does the parity sweep agree with mihomo. None of them
// runs BoxService.Start, which is the entry point the extension calls, and the
// difference showed on 2026-08-28: the macOS lane reported three configurations
// refused on device that every judgement here called acceptable, and neither
// side could say whether the kernel was involved at all.
//
// Driving Start settles the kernel's half in one measurement, and it
// distinguishes the three endings that look alike from outside: returns an
// error, returns nil, or never returns. The last one had a real hypothesis
// behind it -- an http provider whose url cannot be fetched, DefaultHttpTimeout
// being 20s and providers initialising in sequence -- and it is false, which is
// worth pinning so nobody re-derives it.
//
// What it does NOT cover: OpenTun is a stub here, so the real tun request and
// NEPacketTunnelNetworkSettings never happen. A configuration that starts here
// can still fail on a device inside that callback. The boundary is the point --
// this says "the kernel is not the one refusing", which is exactly what nobody
// could establish while the answer was being guessed at from log absence.
func TestConfigurationsThisTreeAcceptsActuallyStart(t *testing.T) {
	setupConfigPipelineTest(t)

	base := "proxies:\n  - {name: N, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-groups:\n  - {name: G, type: select, proxies: [N, DIRECT]}\nrules:\n  - MATCH,G\n"

	for name, document := range map[string]string{
		"plain":                         base,
		"http provider with no url":     base + "rule-providers:\n  r: {type: http, behavior: domain, format: yaml, path: ./r.yaml}\n",
		"file provider that is missing": base + "proxy-providers:\n  p: {type: file, path: ./no-such-provider.yaml}\n",
		// tun.enable is deliberately absent from every case here. The recording
		// platform's OpenTun is a stub, so enabling tun fails with "not
		// implemented yet" -- a refusal about the harness wearing the shape of
		// a refusal about the configuration. route-address-set therefore has no
		// case in this gate; TestFinalizeSkipsNonIPCidrRouteSet covers it where
		// it can be covered honestly.
		"health-check timeout is negative": base + "proxy-providers:\n  p:\n    type: inline\n    payload:\n" +
			"      - {name: M, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: p}\n" +
			"    health-check: {enable: true, url: 'http://e.com', timeout: -1}\n",
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(newRecordingPlatform())
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			defer func() { _ = service.Close() }()

			done := make(chan error, 1)
			begin := time.Now()
			go func() { done <- service.Start(document) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("this tree accepts this configuration everywhere else and Start refuses it "+
						"after %v: %v", time.Since(begin).Round(time.Millisecond), err)
				}
			case <-time.After(45 * time.Second):
				// Not the same failure as an error, and it looks identical from
				// outside the process: a start that never returns is a tunnel
				// the system eventually gives up on, with nothing written
				// anywhere. Named separately so a future regression is not
				// mistaken for a refusal.
				t.Fatalf("Start never returned; a hang is not a refusal and leaves no error to read")
			}
		})
	}
}

// The other side of the same instrument: a configuration the kernel must refuse
// has to come back as an ERROR, quickly, carrying upstream's own words. Without
// this the test above would pass on a Start that accepts everything.
func TestAConfigurationTheKernelMustRefuseComesBackAsAnError(t *testing.T) {
	setupConfigPipelineTest(t)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() { _ = service.Close() }()

	done := make(chan error, 1)
	go func() { done <- service.Start("proxies:\n  - {name: [unclosed\n") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Start accepted a document that is not yaml")
		}
		if !containsAll(err.Error(), "parse config", "did not find expected") {
			t.Fatalf("the refusal does not carry mihomo's own words: %v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("Start never returned on a document that cannot parse")
	}
	_ = os.Getenv
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		found := false
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
