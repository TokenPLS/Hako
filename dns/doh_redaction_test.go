package dns

import (
	"net/url"
	"strings"
	"testing"
)

// A DoH nameserver may carry credentials: userinfo (https://user:pass@…), a
// query token (?token=…), or a path secret -- a NextDNS profile id lives in the
// path, and it is the whole authentication. Upstream keeps the userinfo on
// purpose (config.go builds the upstream URL with url.URL{…, User: u.User}),
// which is correct for reaching the resolver and wrong for anything that prints
// it: url.URL.String renders `user:pass@` in full.
//
// Two printers reach a product log in this fork -- the transport's own debug
// lines, and Address(), which the diagnostics route hands to the App. A log
// line may name which resolver is being used; it may not carry what
// authenticates to it (AGENTS.md §6).

func TestRedactedDNSURLDropsCredentialsAndKeepsIdentity(t *testing.T) {
	parsed, err := url.Parse("https://user:s3cr3t@doh.example.com/dns-query?token=SECRETTOKEN")
	if err != nil {
		t.Fatal(err)
	}
	redacted := redactedDNSURL(parsed)

	for _, secret := range []string{"s3cr3t", "SECRETTOKEN", "user:"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted URL still carries %q: %s", secret, redacted)
		}
	}
	if !strings.Contains(redacted, "doh.example.com") {
		t.Fatalf("redaction destroyed the resolver's identity: %s", redacted)
	}
	if !strings.HasPrefix(redacted, "https://") {
		t.Fatalf("redaction dropped the scheme: %s", redacted)
	}
}

// A NextDNS-style profile id sits in the path and authenticates on its own.
func TestRedactedDNSURLDropsAPathSecret(t *testing.T) {
	parsed, err := url.Parse("https://dns.nextdns.io/abc123profile")
	if err != nil {
		t.Fatal(err)
	}
	redacted := redactedDNSURL(parsed)
	if strings.Contains(redacted, "abc123profile") {
		t.Fatalf("the path secret survived: %s", redacted)
	}
	if !strings.Contains(redacted, "dns.nextdns.io") {
		t.Fatalf("the host must survive: %s", redacted)
	}
}

// An ordinary resolver URL must stay readable -- the point of the line is to
// say which upstream answered.
func TestRedactedDNSURLLeavesAnOrdinaryResolverReadable(t *testing.T) {
	parsed, err := url.Parse("https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if redacted := redactedDNSURL(parsed); !strings.Contains(redacted, "1.1.1.1") {
		t.Fatalf("an ordinary resolver became unreadable: %s", redacted)
	}
}

// Address() is what the diagnostics route hands to the App, so it carries the
// same constraint as the log lines.
func TestDoHAddressCarriesNoCredentials(t *testing.T) {
	doh := newDoHClient("https://user:s3cr3t@doh.example.com/dns-query?token=SECRETTOKEN",
		nil, false, nil, nil, "")
	address := doh.Address()
	for _, secret := range []string{"s3cr3t", "SECRETTOKEN"} {
		if strings.Contains(address, secret) {
			t.Fatalf("Address() exposes %q: %s", secret, address)
		}
	}
	if !strings.Contains(address, "doh.example.com") {
		t.Fatalf("Address() must still name the resolver: %s", address)
	}
}
