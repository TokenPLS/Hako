package hako

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/TokenPLS/Hako/component/age"
	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"gopkg.in/yaml.v3"
)

type recordingProviderCloser struct {
	closeCount int
	closeErr   error
}

func (c *recordingProviderCloser) Close() error {
	c.closeCount++
	return c.closeErr
}

func TestParseAndCloseProviderOutbound(t *testing.T) {
	mapping := map[string]any{"name": "fixture", "type": "direct"}
	t.Run("success closes exactly once", func(t *testing.T) {
		closer := &recordingProviderCloser{}
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, nil
		})
		if err != nil || closer.closeCount != 1 {
			t.Fatalf("validate close = %v, count = %d", err, closer.closeCount)
		}
	})
	t.Run("parse error has no object to close", func(t *testing.T) {
		closer := &recordingProviderCloser{}
		parseErr := errors.New("parse failed")
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, parseErr
		})
		if !errors.Is(err, parseErr) || closer.closeCount != 0 {
			t.Fatalf("parse error = %v, close count = %d", err, closer.closeCount)
		}
	})
	t.Run("close error rejects candidate", func(t *testing.T) {
		closeErr := errors.New("close failed")
		closer := &recordingProviderCloser{closeErr: closeErr}
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, nil
		})
		if !errors.Is(err, closeErr) || closer.closeCount != 1 {
			t.Fatalf("close error = %v, count = %d", err, closer.closeCount)
		}
	})
}

func TestDecryptAgeForIOSUsesExplicitKey(t *testing.T) {
	secret, public, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("payload:\n  - DOMAIN,example.com\n")
	encrypted, err := age.EncryptBytes(plaintext, public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAgeForIOS(encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	if _, err := DecryptAgeForIOS(encrypted, "not-a-key"); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestValidateProviderForIOSAcceptsMRS(t *testing.T) {
	for _, test := range []struct {
		behaviorName string
		behavior     P.RuleBehavior
		text         string
	}{
		{behaviorName: "domain", behavior: P.Domain, text: "example.com\n"},
		{behaviorName: "ipcidr", behavior: P.IPCIDR, text: "10.0.0.0/8\n2001:db8::/32\n"},
	} {
		t.Run(test.behaviorName, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := ruleprovider.ConvertToMrs(
				[]byte(test.text),
				test.behavior,
				P.TextRule,
				&encoded,
			); err != nil {
				t.Fatal(err)
			}
			if err := ValidateProviderForIOS("rule", test.behaviorName, "mrs", encoded.Bytes()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProviderEntryCountForIOS(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		behavior string
		format   string
		payload  []byte
		want     int
	}{
		{
			name: "proxy yaml", kind: "proxy", format: "yaml", want: 2,
			payload: []byte("proxies:\n  - {name: One, type: direct}\n  - {name: Two, type: direct}\n"),
		},
		{
			name: "domain yaml", kind: "rule", behavior: "domain", format: "yaml", want: 2,
			payload: []byte("payload:\n  - example.com\n  - example.net\n"),
		},
		{
			name: "ipcidr text", kind: "rule", behavior: "ipcidr", format: "text", want: 2,
			payload: []byte("# ignored\n192.0.2.0/24\n198.51.100.0/24\n"),
		},
		{
			name: "classical yaml", kind: "rule", behavior: "classical", format: "yaml", want: 2,
			payload: []byte("payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.net\n"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ProviderEntryCountForIOS(
				test.kind, test.behavior, test.format, test.payload,
			)
			if err != nil {
				t.Fatalf("ProviderEntryCountForIOS: %v", err)
			}
			if got != test.want {
				t.Fatalf("count = %d, want %d", got, test.want)
			}
		})
	}
}

// The count round-trips from an MRS the kernel itself wrote. Renamed from
// ...ReadsValidatedMRSCount: nothing validates the header count any more, so the
// old name promised a guarantee that no longer exists.
func TestProviderEntryCountForIOSRoundTripsAKernelWrittenMRS(t *testing.T) {
	var encoded bytes.Buffer
	if err := ruleprovider.ConvertToMrs(
		[]byte("example.com\nexample.net\n"),
		P.Domain,
		P.TextRule,
		&encoded,
	); err != nil {
		t.Fatalf("build mrs: %v", err)
	}
	got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", encoded.Bytes())
	if err != nil {
		t.Fatalf("ProviderEntryCountForIOS: %v", err)
	}
	if got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}

// Was TestProviderEntryCountForIOSRejectsInvalidPayload, asserting that
// `payload: []` for a domain provider is refused. That is not an invalid payload,
// it is an empty one, and upstream loads it as zero rules -- the assertion pinned
// our own overreach, which is how the overreach survived the previous audit. It
// now asserts the shape that IS invalid: a body upstream's parser cannot find a
// list in at all.
func TestProviderEntryCountForIOSRejectsUnparseablePayload(t *testing.T) {
	if _, err := ProviderEntryCountForIOS(
		"rule", "domain", "yaml", []byte("payload:"),
	); err == nil {
		t.Fatal("a body with no payload head was accepted; upstream returns ErrNoPayload")
	}
	count, err := ProviderEntryCountForIOS(
		"rule", "domain", "yaml", []byte("payload: []\n"),
	)
	if err != nil {
		t.Fatalf("an empty list was rejected; upstream reads it as zero rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("empty list counted %d, want 0", count)
	}
}

func TestValidateProviderForIOSRejectsUnsafeMRSLengthsWithoutPanicking(t *testing.T) {
	tests := map[string][]byte{
		"oversized extra": buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		}),
		"oversized domain leaves length": buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			output.WriteByte(1)
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		}),
	}
	for name, decoded := range tests {
		t.Run(name, func(t *testing.T) {
			payload := compressMRSTestPayload(t, decoded)
			var panicValue any
			var err error
			func() {
				defer func() { panicValue = recover() }()
				err = ValidateProviderForIOS("rule", "domain", "mrs", payload)
			}()
			if panicValue != nil {
				t.Fatalf("unsafe MRS panicked: %v", panicValue)
			}
			if err == nil {
				t.Fatal("unsafe MRS was accepted")
			}
		})
	}
}

func TestValidateProviderForIOSBoundsMRSDecompression(t *testing.T) {
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
		if err := binary.Write(output, binary.BigEndian, int64(maximumProviderResourceBytes)); err != nil {
			t.Fatal(err)
		}
		output.Write(bytes.Repeat([]byte{0}, maximumProviderResourceBytes))
	})
	payload := compressMRSTestPayload(t, decoded)
	if len(payload) >= maximumProviderResourceBytes {
		t.Fatalf("compressed fixture unexpectedly exceeds input cap: %d", len(payload))
	}
	err := ValidateProviderForIOS("rule", "domain", "mrs", payload)
	if err == nil || !strings.Contains(err.Error(), "decoded MRS payload exceeds") {
		t.Fatalf("MRS decompression limit error = %v", err)
	}
}

func buildDecodedMRSTestPayload(t *testing.T, behavior P.RuleBehavior, count int64, appendBody func(*bytes.Buffer)) []byte {
	t.Helper()
	var decoded bytes.Buffer
	decoded.Write(ruleprovider.MrsMagicBytes[:])
	decoded.WriteByte(behavior.Byte())
	if err := binary.Write(&decoded, binary.BigEndian, count); err != nil {
		t.Fatal(err)
	}
	appendBody(&decoded)
	return decoded.Bytes()
}

func compressMRSTestPayload(t *testing.T, decoded []byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	encoder, err := zstd.NewWriter(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}

func TestValidateProviderForIOS(t *testing.T) {
	for _, test := range []struct {
		name, kind, behavior, format string
		payload                      []byte
		wantError                    bool
	}{
		{name: "rule yaml", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - DOMAIN,example.com\n")},
		{name: "rule text", kind: "rule", behavior: "domain", format: "text", payload: []byte("example.com\n")},
		{name: "proxy yaml", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n")},
		{name: "proxy share links", kind: "proxy", format: "yaml", payload: []byte("hysteria2://password@example.com:443/?sni=example.com#one\n")},
		{name: "proxy wrong root field", kind: "proxy", format: "yaml", payload: []byte("payload:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n"), wantError: true},
		// interface-name/routing-mark egress overrides are stripped (tolerate +
		// strip), so a provider proxy carrying one loads instead of erroring.
		{name: "proxy interface override tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    interface-name: en0\n")},
		{name: "proxy routing mark tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    routing-mark: 233\n")},
		{name: "paired proxy egress overrides tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    interface-name: en0\n    routing-mark: 233\n")},
		{name: "domain payload named like metadata", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - DOMAIN,process-name\n")},
		{name: "empty", kind: "rule", behavior: "classical", format: "yaml", payload: nil, wantError: true},
		// A malformed payload CONTAINER (mapping where a rule list is required) is a
		// structural parse failure and is still rejected. A single malformed rule
		// ENTRY is now tolerated (skipped) — see TestClassicalProviderSkips... .
		{name: "malformed payload container", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  key: value\n"), wantError: true},
		{name: "process wildcard rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - PROCESS-NAME-WILDCARD,curl*\n")},
		{name: "uid rule", kind: "rule", behavior: "classical", format: "text", payload: []byte("UID,501\n")},
		{name: "in-user rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - IN-USER,alice\n")},
		{name: "logic nested metadata rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - AND,((PROCESS-PATH-REGEX,^/bin/.*),(NETWORK,TCP))\n")},
		{name: "bad proxy", kind: "proxy", format: "yaml", payload: []byte("payload:\n  - server: x\n"), wantError: true},
		{name: "proxy mrs", kind: "proxy", format: "mrs", payload: []byte("not mrs"), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateProviderForIOS(test.kind, test.behavior, test.format, test.payload)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestProviderEntryCountForIOSExcludesMetadataNoOps(t *testing.T) {
	payload := []byte(`
payload:
  - PROCESS-NAME,curl
  - DOMAIN,first.example
  - UID,501
  - IN-USER,alice
  - DOMAIN,second.example
`)
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("executable provider entry count = %d, want 2", count)
	}
}

func TestClassicalProviderSkipsUnsupportedEntryInsteadOfFailingWholeSet(t *testing.T) {
	// Upstream classicalStrategy.Insert warn-skips an unparseable or unsupported
	// classical entry and keeps the rest. A pinned core that lags a subscription's
	// newest rule keyword must not fail the whole provider (which would also refuse
	// to start the config); it drops the single entry and keeps the executable ones.
	payload := []byte(`
payload:
  - DOMAIN,keep.example
  - RULE-SET,unsupported-nested-set
  - DOMAIN-SUFFIX,also.example
`)
	if err := ValidateProviderForIOS("rule", "classical", "yaml", payload); err != nil {
		t.Fatalf("classical provider with one unsupported entry must load, got: %v", err)
	}
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("kept executable entry count = %d, want 2 (unsupported entry skipped)", count)
	}
}

func TestClassicalProviderLoadsEmptyWhenEveryEntryIsSkipped(t *testing.T) {
	// Upstream parity: when every entry is unsupported the provider loads with
	// zero rules (matching nothing), exactly like an all-metadata provider — it is
	// never failed wholesale. (classicalProviderEntries still rejects a payload
	// with no entries at all; that empty-file case is separate and unchanged.)
	payload := []byte(`
payload:
  - RULE-SET,one
  - SUB-RULE,(two)
`)
	if err := ValidateProviderForIOS("rule", "classical", "yaml", payload); err != nil {
		t.Fatalf("all-unsupported classical provider must load empty, got: %v", err)
	}
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("kept executable entry count = %d, want 0", count)
	}
}

func TestValidateProviderForIOSRejectsIgnoredNestedDNSFragment(t *testing.T) {
	payload := []byte(`
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "nested DNS fragment") {
		t.Fatalf("ignored provider nested DNS fragment accepted: %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteriaHopInterval(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    ports: 443-444
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 hop-interval") {
		t.Fatalf("unsafe provider Hysteria hop interval error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteria2HopInterval(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    ports: 443-444
    password: fixture
    hop-interval: 5-9223372037
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 hop-interval") {
		t.Fatalf("unsafe provider Hysteria2 hop interval error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeAnyTLSIdleSessionInterval(t *testing.T) {
	payload := []byte(`
proxies:
  - name: ANYTLS
    type: anytls
    server: 127.0.0.1
    port: 443
    password: fixture
    idle-session-check-interval: 9223372037
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 idle-session-check-interval") {
		t.Fatalf("unsafe provider AnyTLS interval error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeKcptunKeepalive(t *testing.T) {
	payload := []byte(`
proxies:
  - name: SS
    type: ss
    server: 127.0.0.1
    port: 443
    cipher: aes-128-gcm
    password: fixture
    plugin: kcptun
    plugin-opts:
      keepalive: -1
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 plugin-opts.keepalive") {
		t.Fatalf("unsafe provider kcptun keepalive error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeTUICDatagramFrameSize(t *testing.T) {
	payload := []byte(`
proxies:
  - name: TUIC
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    password: fixture
    max-datagram-frame-size: 1
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 max-datagram-frame-size") {
		t.Fatalf("unsafe provider TUIC datagram frame size error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteria2FlowControlWindow(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: fixture
    initial-connection-receive-window: 4611686018427387904
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 initial-connection-receive-window") {
		t.Fatalf("unsafe provider Hysteria2 flow-control window error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteriaRate(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    auth-str: fixture
    up: 18446745 TBps
    down: 10 Mbps
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 up") {
		t.Fatalf("unsafe provider Hysteria rate error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteria2AndBrutalRates(t *testing.T) {
	tests := map[string]struct {
		payload []byte
		field   string
	}{
		"Hysteria2": {
			payload: []byte(`
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: fixture
    down: 18446745 TBps
`),
			field: "down",
		},
		"sing-mux Brutal": {
			payload: []byte(`
proxies:
  - name: DIRECT-MUX
    type: direct
    smux:
      enabled: true
      brutal-opts:
        enabled: true
        up: 18446745 TBps
`),
			field: "smux.brutal-opts.up",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateProviderForIOS("proxy", "", "yaml", test.payload)
			if err == nil || !strings.Contains(err.Error(), "item 0 "+test.field) {
				t.Fatalf("unsafe provider outbound rate error = %v", err)
			}
		})
	}
}

func TestValidateProviderForIOSRejectsUnsafeBBRCongestionWindow(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: fixture
    cwnd: 7205759403792794
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 cwnd") {
		t.Fatalf("unsafe provider BBR congestion window error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeHysteria2UDPMTU(t *testing.T) {
	payload := []byte(`
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: fixture
    udp-mtu: -1
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 udp-mtu") {
		t.Fatalf("unsafe provider Hysteria2 UDP MTU error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeTUICMaxOpenStreams(t *testing.T) {
	payload := []byte(`
proxies:
  - name: TUIC
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    password: fixture
    max-open-streams: -1
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 max-open-streams") {
		t.Fatalf("unsafe provider TUIC maximum open streams error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnboundedXHTTPGeneratedBuffer(t *testing.T) {
	payload := []byte(`
proxies:
  - name: VLESS
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: xhttp
    xhttp-opts:
      x-padding-bytes: 4194305
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 xhttp-opts.x-padding-bytes") {
		t.Fatalf("unbounded provider XHTTP generated buffer error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeXHTTPReuseRange(t *testing.T) {
	payload := []byte(`
proxies:
  - name: VLESS
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: xhttp
    xhttp-opts:
      reuse-settings:
        c-max-reuse-times: 2147483648
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 xhttp-opts.reuse-settings.c-max-reuse-times") {
		t.Fatalf("unsafe provider XHTTP reuse range error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeKcptunConnectionCount(t *testing.T) {
	payload := []byte(`
proxies:
  - name: SS
    type: ss
    server: 127.0.0.1
    port: 443
    cipher: aes-128-gcm
    password: fixture
    plugin: kcptun
    plugin-opts:
      conn: 65536
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 plugin-opts.conn") {
		t.Fatalf("unsafe provider kcptun connection count error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeKcptunFECShards(t *testing.T) {
	payload := []byte(`
proxies:
  - name: SS
    type: ss
    server: 127.0.0.1
    port: 443
    cipher: aes-128-gcm
    password: fixture
    plugin: kcptun
    plugin-opts:
      datashard: 254
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 plugin-opts.parityshard") {
		t.Fatalf("unsafe provider kcptun FEC shard error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeKcptunSmuxSettings(t *testing.T) {
	payload := []byte(`
proxies:
  - name: SS
    type: ss
    server: 127.0.0.1
    port: 443
    cipher: aes-128-gcm
    password: fixture
    plugin: kcptun
    plugin-opts:
      smuxbuf: 1024
      streambuf: 1025
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 plugin-opts.streambuf") {
		t.Fatalf("unsafe provider kcptun smux setting error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeKcptunTransportSettings(t *testing.T) {
	payload := []byte(`
proxies:
  - name: SS
    type: ss
    server: 127.0.0.1
    port: 443
    cipher: aes-128-gcm
    password: fixture
    plugin: kcptun
    plugin-opts:
      ratelimit: 4294967296
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 plugin-opts.ratelimit") {
		t.Fatalf("unsafe provider kcptun transport setting error = %v", err)
	}
}

func TestValidateProviderForIOSRejectsUnsafeXHTTPPacketUpScheduling(t *testing.T) {
	payload := []byte(`
proxies:
  - name: VLESS
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: xhttp
    xhttp-opts:
      mode: packet-up
      sc-min-posts-interval-ms: 0-9223372036854775807
`)
	err := ValidateProviderForIOS("proxy", "", "yaml", payload)
	if err == nil || !strings.Contains(err.Error(), "item 0 xhttp-opts.sc-min-posts-interval-ms") {
		t.Fatalf("unsafe provider XHTTP packet-up scheduling error = %v", err)
	}
}

// A classical rule-provider with a `payload:` head and no items under it is a
// provider with zero rules, not a broken file. Upstream's parser
// (rules/provider/provider.go:175-266) finds the head, skips comment and blank
// lines, and falls out of the loop to `strategy.FinishInsert(); return strategy,
// nil` -- no error, a provider whose Count() is 0. Nothing downstream minds:
// the rule set simply matches nothing.
//
// Rejecting it here does mind, and expensively: an empty provider stops the
// whole configuration from starting on iOS while the same file runs everywhere
// else. Providers go empty for ordinary reasons -- a category upstream cleared,
// a file the user has not filled in yet, a subscription that returns nothing for
// a list this week.
func TestEmptyClassicalProviderIsZeroRulesNotAnError(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("payload:\n"),
		[]byte("payload:\n  # nothing in this list yet\n"),
	} {
		if err := validateClassicalProvider(payload, P.YamlRule); err != nil {
			t.Errorf("rejected %q, which upstream reads as zero rules: %v",
				string(payload), err)
		}
	}
	if err := validateClassicalProvider([]byte("# nothing yet\n"), P.TextRule); err != nil {
		t.Errorf("rejected a comment-only text provider, which upstream reads as "+
			"zero rules: %v", err)
	}
}

// Upstream accepts two spellings for a classical rule list -- `payload:` and
// `rules:` (rules/provider/provider.go:26-33, RulePayload). Hako read only the
// first, and while the empty-payload rejection existed that mismatch surfaced as
// a loud (if misworded) refusal. Removing the rejection turned it into silence:
// a `rules:`-keyed provider now yields zero entries, so the Apple-unavailable
// metadata strip runs over nothing and the original bytes are handed back
// untouched, while the App is told the provider has 0 rules.
//
// That is worse than either the old behaviour or the correct one. The fix is to
// read both keys, the way upstream's own struct does.
func TestClassicalProviderReadsBothPayloadAndRulesKeys(t *testing.T) {
	body := []byte("rules:\n  - PROCESS-NAME,evil,DIRECT\n  - DOMAIN-SUFFIX,example.com,DIRECT\n")

	sanitized, count, stripped, err := sanitizeClassicalProviderPayloadForIOS(body, P.YamlRule)
	if err != nil {
		t.Fatalf("rules-keyed provider rejected: %v", err)
	}
	if count == 0 {
		t.Fatalf("counted 0 entries for a provider with 2 rules; the `rules:` key was ignored")
	}
	if len(stripped) == 0 {
		t.Errorf("PROCESS-NAME survived the Apple metadata strip in a rules-keyed provider")
	}
	if string(sanitized) == string(body) {
		t.Errorf("payload was handed back untouched, so nothing was sanitized")
	}
}

// One shape upstream genuinely refuses, and preflight must refuse it too.
//
// `rulesParse` scans for a `payload:`/`rules:` head line by line; if it reaches
// the end of the buffer without having found one it returns ErrNoPayload
// (rules/provider/provider.go:186-199). The head is only recognised on a line,
// so `payload:` with NO trailing newline never registers -- upstream reports
// "file must have a `payload` field" while `payload:\n` parses to zero rules.
//
// Deleting the blanket empty-payload rejection let this shape through as well,
// which is the one case where relaxing went too far:'s whole purpose is
// that a provider error surfaces during preflight rather than after the active
// revision pointer has flipped. Zero rules is fine; a payload upstream cannot
// parse at all is not.
func TestClassicalProviderWithoutPayloadHeadIsStillRejected(t *testing.T) {
	if err := validateClassicalProvider([]byte("payload:"), P.YamlRule); err == nil {
		t.Error("accepted a YAML payload with no head line; upstream returns ErrNoPayload")
	}
	if err := validateClassicalProvider([]byte("# nothing"), P.YamlRule); err == nil {
		t.Error("accepted a comment-only YAML body with no head line; upstream returns ErrNoPayload")
	}
	// The newline-terminated forms stay accepted: those are zero rules, not a
	// missing payload field.
	for _, ok := range [][]byte{[]byte("payload:\n"), []byte("rules:\n")} {
		if err := validateClassicalProvider(ok, P.YamlRule); err != nil {
			t.Errorf("rejected %q, which upstream parses to zero rules: %v", string(ok), err)
		}
	}
}

// The empty-provider fix has to cover domain and ipcidr, not just classical.
//
// Those behaviours are validated by handing the payload to
// `ruleprovider.ConvertToMrs`, which refuses `strategy.Count() == 0` with
// "empty rule" (rules/provider/mrs_converter.go:21-23). That is a WRITER
// precondition -- do not serialise an empty .mrs -- and it has no counterpart on
// the load path a running config takes, where `rulesParse` returns a zero-rule
// strategy and mihomo carries on. Borrowing it as a read-time gate made
// `behavior: domain` the stricter case, and downloaded rule lists are far more
// often domain than classical, so the half left unfixed was the likelier one.
func TestEmptyDomainAndIPCIDRProvidersAreZeroRulesToo(t *testing.T) {
	for _, c := range []struct{ behavior, format, body string }{
		{"domain", "yaml", "payload:\n"},
		{"domain", "yaml", "payload: []\n"},
		{"domain", "text", "# nothing in this list yet\n"},
		{"ipcidr", "yaml", "payload:\n"},
	} {
		if err := ValidateProviderForIOS("rule", c.behavior, c.format, []byte(c.body)); err != nil {
			t.Errorf("%s/%s %q rejected; upstream loads it as zero rules: %v",
				c.behavior, c.format, c.body, err)
		}
		count, err := ProviderEntryCountForIOS("rule", c.behavior, c.format, []byte(c.body))
		if err != nil {
			t.Errorf("%s/%s %q count failed: %v", c.behavior, c.format, c.body, err)
		} else if count != 0 {
			t.Errorf("%s/%s %q counted %d, want 0", c.behavior, c.format, c.body, count)
		}
	}
}

// Pins the coupling the fix above depends on. It recognises upstream's empty
// case by matching the error text of `ConvertToMrs`, because that error is an
// inline `errors.New` with no sentinel to compare against and reimplementing
// upstream's line parser is the wrong trade -- the last audit round established
// that a second decode path costs a real bug per review cycle.
//
// If an upstream bump rewords this, the failure lands here as a red test rather
// than silently restoring the rejection this file exists to remove.
func TestUpstreamEmptyRuleErrorTextIsUnchanged(t *testing.T) {
	err := ruleprovider.ConvertToMrs([]byte("payload:\n"), P.Domain, P.YamlRule, io.Discard)
	if err == nil {
		t.Fatal("ConvertToMrs accepted an empty rule set; the guard below is now dead code")
	}
	if err.Error() != upstreamEmptyRuleMessage {
		t.Fatalf("ConvertToMrs empty-set error = %q, want %q; update "+
			"isUpstreamEmptyRuleError and re-check the empty-provider paths",
			err.Error(), upstreamEmptyRuleMessage)
	}
}

// One parse, both answers, and the same sentence a reader used to be shown.
//
// The App called validate and then count, which parsed every payload twice —
// 53 rule sets in one reader's profile, each parsed twice on every profile
// switch, and for a text list one parse is a full conversion. This pins that
// collapsing them keeps every verdict identical.
func TestInspectProviderMatchesValidateThenCount(t *testing.T) {
	classical := []byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,www.example.org\n")
	unreadable := []byte("payload: not-a-list\n")
	notMRS := []byte("this is not a compiled rule set at all")

	for name, testCase := range map[string]struct {
		kind, behavior, format string
		payload                []byte
	}{
		"classical accepted":  {"rule", "classical", "yaml", classical},
		"classical unusable":  {"rule", "classical", "yaml", unreadable},
		"mrs that is not mrs": {"rule", "domain", "mrs", notMRS},
		"unknown kind":        {"widget", "domain", "yaml", classical},
		"empty payload":       {"rule", "domain", "yaml", nil},
	} {
		t.Run(name, func(t *testing.T) {
			validateErr := ValidateProviderForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)
			wantCount, countErr := ProviderEntryCountForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)
			gotCount, gotErr := InspectProviderForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)

			if (validateErr == nil) != (gotErr == nil) {
				t.Fatalf("validate said %v, one-pass said %v", validateErr, gotErr)
			}
			if validateErr != nil {
				if gotErr.Error() != validateErr.Error() {
					t.Fatalf("one-pass reported %q, validate reported %q",
						gotErr.Error(), validateErr.Error())
				}
				return
			}
			if countErr != nil {
				t.Fatalf("count failed where validate passed: %v", countErr)
			}
			if gotCount != wantCount {
				t.Fatalf("count = %d, want %d", gotCount, wantCount)
			}
		})
	}
}

func TestConvertProxiesForIOSTurnsAShareLinkIntoAProxyDocument(t *testing.T) {
	link := []byte("hysteria2://password@example.com:443/?sni=example.com#one\n")
	box, err := ConvertProxiesForIOS(link)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(box.Value), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(doc.Proxies))
	}
	if got := doc.Proxies[0]["name"]; got != "one" {
		t.Fatalf("name = %v, want one", got)
	}
	if got := doc.Proxies[0]["server"]; got != "example.com" {
		t.Fatalf("server = %v, want example.com", got)
	}
}

func TestConvertProxiesForIOSRefusesTextThatIsNotProxies(t *testing.T) {
	if _, err := ConvertProxiesForIOS([]byte("not a share link")); err == nil {
		t.Fatal("want an error for unconvertible text")
	}
}

func TestConvertProxiesForIOSRefusesAnEmptyPayload(t *testing.T) {
	if _, err := ConvertProxiesForIOS(nil); err == nil {
		t.Fatal("want an error for an empty payload")
	}
}
