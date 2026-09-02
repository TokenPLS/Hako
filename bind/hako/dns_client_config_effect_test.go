package hako

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/hub/executor"
	D "github.com/miekg/dns"
)

// The client's DNS editor writes a `dns:` block; this proves the kernel then
// asks the servers it names.
//
// Everything above this line in the client is editor and generator coverage:
// the UI round-trips its own draft, and `ProfileRuntimeConfigBuilder` is
// asserted to put those values in the generated YAML. Neither says the
// resolution a user gets actually goes to those servers — that claim needs
// the kernel, a controlled resolver, and an observed query.
//
// The config shape is the one our editor produces: enable + nameserver +
// default-nameserver (pure IP, config/config.go:1460-1470) + a
// nameserver-policy entry, which is exactly the trio the DNS hub saves.
func TestClientDNSConfigDecidesWhoResolves(t *testing.T) {
	// No Setup(): the persistent cache is a process-wide sync.Once that the
	// first real core start claims (setup_test.go:189), and this test needs
	// none of it — the executor path parses and applies a config on its own,
	// which is precisely the layer under test.
	general, generalAddress, generalQueries := startControlledDNSServer(t, "udp")
	defer func() { _ = general.Shutdown() }()
	policy, policyAddress, policyQueries := startControlledDNSServer(t, "udp")
	defer func() { _ = policy.Shutdown() }()

	configYAML := fmt.Sprintf(`
mode: rule
dns:
  enable: true
  listen: ""
  enhanced-mode: redir-host
  default-nameserver:
    - %s
  nameserver:
    - %s
  nameserver-policy:
    "policy.controlled.test": %s
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: pick, type: select, proxies: [a]}
rules:
  - MATCH,pick
`, generalAddress, generalAddress, policyAddress)

	configuration, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("ParseWithBytes() error = %v\n%s", err, configYAML)
	}
	executor.ApplyConfig(configuration, true)
	if resolver.DefaultResolver == nil {
		t.Fatal("applying a dns block must install a resolver")
	}

	// Drain anything the apply itself provoked, so each assertion below is
	// about its own query.
	drain(generalQueries)
	drain(policyQueries)

	// 1. An ordinary name goes to the configured nameserver, and the answer
	//    the user gets is the one that server returned.
	answer := exchange(t, "a.controlled.test.")
	if len(answer.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(answer.Answer))
	}
	if got := answer.Answer[0].(*D.A).A.String(); got != "192.0.2.10" {
		t.Fatalf("resolved %s, want the controlled server's 192.0.2.10", got)
	}
	if !observedWithin(generalQueries, 2*time.Second) {
		t.Fatal("the query never reached the configured nameserver")
	}

	// 2. A name covered by nameserver-policy goes to that policy's server
	//    instead — the editor's policy rows are not decoration.
	if _, err := resolver.DefaultResolver.ExchangeContext(
		contextWithTimeout(t), question("policy.controlled.test."),
	); err != nil {
		t.Fatalf("policy query error = %v", err)
	}
	if !observedWithin(policyQueries, 2*time.Second) {
		t.Fatal("a policied name did not reach its policy resolver")
	}
	if observedWithin(generalQueries, 300*time.Millisecond) {
		t.Fatal("a policied name must not fall through to the general nameserver")
	}
}

func exchange(t *testing.T, name string) *D.Msg {
	t.Helper()
	response, err := resolver.DefaultResolver.ExchangeContext(
		contextWithTimeout(t), question(name),
	)
	if err != nil {
		t.Fatalf("ExchangeContext(%s) error = %v", name, err)
	}
	return response
}

func question(name string) *D.Msg {
	msg := new(D.Msg)
	msg.SetQuestion(name, D.TypeA)
	return msg
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func observedWithin(queries <-chan string, wait time.Duration) bool {
	select {
	case <-queries:
		return true
	case <-time.After(wait):
		return false
	}
}

func drain(queries <-chan string) {
	for {
		select {
		case <-queries:
		default:
			return
		}
	}
}
