package hako

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TokenPLS/Hako/adapter/outbound"
	"github.com/TokenPLS/Hako/component/ca"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/common/convert"
	"github.com/TokenPLS/Hako/config"
	"gopkg.in/yaml.v3"
)

type proxyImportCapability struct {
	Scheme        string `json:"scheme"`
	CanonicalType string `json:"canonicalType,omitempty"`
	Status        string `json:"status"`
	// PasteRole is the routing decision for a pasted string: the registry owns it
	// so a client never re-derives which scheme is a node and which is a link to
	// fetch. Status answers "can the Core build it", PasteRole answers "which door
	// does this belong to"; a scheme can be a node the Core cannot construct.
	PasteRole string `json:"pasteRole"`
}

type proxyImportCapabilitiesDocument struct {
	Schemes  []proxyImportCapability `json:"schemes"`
	Contexts []string                `json:"contexts"`
}

type proxyImportIssue struct {
	Index  int    `json:"index"`
	Scheme string `json:"scheme"`
	Code   string `json:"code"`
	// Line and Offset locate a share-link record inside the text the reader
	// pasted, counting from one and from zero respectively. Container formats
	// (JSON, YAML, INI) leave both at zero: there Index is the array position,
	// which is what locates an entry in that shape.
	Line    int    `json:"line,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Message string `json:"message"`
	// Which node this field belongs to, by the name the node ends up with.
	// Index would have been the obvious key and is the wrong one: the client
	// filters and sorts before it renders, and an index into the array it was
	// handed stops meaning anything the moment it does. Names are unique inside
	// one import -- makeProxyImportNameUnique guarantees it -- and are already
	// this tree's identity for a proxy. Set only on NotHonoured entries.
	Proxy string `json:"proxy,omitempty"`
	// Fields the same record named that this build could not honour, on a
	// record that was skipped for some other reason. They ride with the skip
	// rather than going to NotHonoured, where they would name a node that does
	// not exist. One link with two problems is one thing that happened to the
	// person; two arrays each holding half of it is not.
	AlsoNotHonoured []string `json:"alsoNotHonoured,omitempty"`
}

type proxyImportUnsupportedFieldError struct {
	field  string
	detail string
}

func (e *proxyImportUnsupportedFieldError) Error() string {
	return fmt.Sprintf("hako: proxy field %q is recognized but unsupported: %s", e.field, e.detail)
}

func unsupportedProxyImportField(field, detail string) error {
	return &proxyImportUnsupportedFieldError{field: field, detail: detail}
}

type proxyImportReport struct {
	Format  string           `json:"format"`
	Context string           `json:"context"`
	Proxies []map[string]any `json:"proxies"`
	// Two outcomes, because there were never three. A record either became a
	// node or it did not, and "recognized but unsupported" was a third name for
	// the second one -- the only consumer of it, the client's import bridge,
	// had been concatenating it with the rejections since the day it was
	// written. The reader's ruling on 2026-08-28: parse what parses, skip what
	// does not, and say what was skipped.
	Skipped []proxyImportIssue `json:"skipped"`
	// Fields that did not survive on a node that did. This is not a third
	// outcome: every one of these belongs to a proxy in Proxies above, named by
	// the Proxy field, and a client that ignores them still imports correctly.
	NotHonoured []proxyImportIssue `json:"notHonoured"`
	// One identity per node in Proxies, in the same order, produced in the same
	// pass -- the two arrays cannot drift apart because neither is appended to
	// without the other. Two entries with the same identity are the same node
	// pasted twice, and the client decides what to do about that: collapsing
	// belongs where the person's existing profile is visible, and this pass sees
	// only what was pasted just now.
	Identities   []string                 `json:"identities"`
	PayloadShape *proxyImportPayloadShape `json:"payloadShape,omitempty"`
}

// proxyImportPayloadShape answers "what is this document" separately from "what
// proxies did it yield". A configuration whose nodes all come from
// `proxy-providers`, and one that only carries rules, are both valid and both
// hold zero inline proxies -- and an expired subscription that answers
// `{"code":401}` is valid YAML that holds zero inline proxies too. Reporting only
// the proxy count makes those indistinguishable, and a caller that has to tell
// them apart ends up keeping its own copy of mihomo's vocabulary.
type proxyImportPayloadShape struct {
	IsConfiguration   bool     `json:"isConfiguration"`
	RecognizedKeys    []string `json:"recognizedKeys"`
	UnrecognizedKeys  []string `json:"unrecognizedKeys"`
	HasInlineProxies  bool     `json:"hasInlineProxies"`
	HasProxyProviders bool     `json:"hasProxyProviders"`
}

// mihomoConfigurationKeys is every top-level key the kernel's own RawConfig
// declares, read off its yaml tags by reflection. A second copy of upstream's
// vocabulary maintained by hand goes stale the day upstream adds a field, and
// nothing tells us: the client that asked for this had hand-written 24
// of the 65 keys this returns.
var mihomoConfigurationKeys = func() map[string]struct{} {
	keys := make(map[string]struct{})
	var collect func(reflect.Type)
	collect = func(structType reflect.Type) {
		for index := 0; index < structType.NumField(); index++ {
			field := structType.Field(index)
			tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
				collect(field.Type)
				continue
			}
			if tag == "" || tag == "-" {
				continue
			}
			keys[tag] = struct{}{}
		}
	}
	collect(reflect.TypeOf(config.RawConfig{}))
	return keys
}()

// describeProxyImportPayloadShape classifies a decoded top-level document.
func describeProxyImportPayloadShape(document map[string]any) *proxyImportPayloadShape {
	shape := &proxyImportPayloadShape{
		RecognizedKeys:   make([]string, 0, len(document)),
		UnrecognizedKeys: make([]string, 0),
	}
	for key := range document {
		if _, known := mihomoConfigurationKeys[key]; known {
			shape.RecognizedKeys = append(shape.RecognizedKeys, key)
			continue
		}
		shape.UnrecognizedKeys = append(shape.UnrecognizedKeys, key)
	}
	sort.Strings(shape.RecognizedKeys)
	sort.Strings(shape.UnrecognizedKeys)
	shape.IsConfiguration = len(shape.RecognizedKeys) > 0
	if raw, ok := document["proxies"]; ok {
		if list, ok := raw.([]any); ok && len(list) > 0 {
			shape.HasInlineProxies = true
		}
	}
	if raw, ok := document["proxy-providers"]; ok {
		if providers, ok := raw.(map[string]any); ok && len(providers) > 0 {
			shape.HasProxyProviders = true
		}
	}
	return shape
}

const (
	proxyImportSupported       = "supported"
	proxyImportCoreUnsupported = "coreUnsupported"
	proxyImportSemanticReview  = "semanticReview"
	proxyImportWrapper         = "wrapper"
)

const (
	proxyImportPasteNode         = "node"
	proxyImportPasteSubscription = "subscription"
	proxyImportPasteWrapper      = "wrapper"
)

// This is the single import registry. Its order follows Shadowrocket 2.2.90's
// supportsSchemes output so drift is visible in one exact comparison rather
// than being hidden by a set.
var proxyImportCapabilities = []proxyImportCapability{
	{Scheme: "vmess", CanonicalType: "vmess", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "http", CanonicalType: "http", Status: proxyImportSupported, PasteRole: proxyImportPasteSubscription},
	{Scheme: "https", CanonicalType: "http", Status: proxyImportSupported, PasteRole: proxyImportPasteSubscription},
	{Scheme: "http2", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "http3", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks5", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks5h", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssocks", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssocks5", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "lua", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssr", CanonicalType: "ssr", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "sub", Status: proxyImportWrapper, PasteRole: proxyImportPasteWrapper},
	{Scheme: "trojan", CanonicalType: "trojan", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "trojan-go", CanonicalType: "trojan", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ss", CanonicalType: "ss", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "gp", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "snell", CanonicalType: "snell", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "vless", CanonicalType: "vless", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "relay", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hysteria", CanonicalType: "hysteria", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy", CanonicalType: "hysteria", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hysteria2", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy2", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	// Upstream builds a proxy from these too (common/convert/converter.go: the
	// "+realm" suffix switches on realm-opts). Not Shadowrocket spellings, but
	// the core we feed accepts them, so refusing them here would make the
	// importer narrower than the thing it hands the payload to.
	{Scheme: "hysteria2+realm", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy2+realm", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "tuic", CanonicalType: "tuic", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "juicity", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "wireguard", CanonicalType: "wireguard", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "wg", CanonicalType: "wireguard", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "masque", CanonicalType: "masque", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssh", CanonicalType: "ssh", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "anytls", CanonicalType: "anytls", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "openconnect", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "tt", CanonicalType: "trusttunnel", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "mierus", CanonicalType: "mieru", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "mieru", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "brook", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
}

// proxyImportQueryFieldLedger is the fail-closed input contract for share-link
// query fields. Every accepted key must either be mapped into the canonical
// mihomo proxy, be explicitly metadata-only, or be rejected later as a known
// but unrepresentable field. The inventory includes the spellings emitted by
// Shadowrocket 2.2.90 (3378), not just the spellings preferred by mihomo.
var proxyImportQueryFieldLedger = map[string]map[string]struct{}{
	"vmess": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "uot", "padding", "fragment",
		"alterId", "tls", "xtls", "peer", "sni", "serverName", "tlsServerName", "allowInsecure",
		"allow_insecure", "insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp", "pcs",
		"pbk", "publicKey", "sid", "shortId", "obfs", "obfsParam", "security", "packetEncoding",
		"type", "headerType", "host", "method", "path", "ed", "eh", "serviceName", "mode", "extra",
		"encryption",
	),
	"http": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "method", "tls", "security", "peer", "sni",
		"serverName", "tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify",
		"fingerprint", "hpkp", "fragment", "pbk", "publicKey", "sid", "shortId",
	),
	// `security` sits beside `tls` here for the reason it already does on
	// trojan, vless, vmess and snell: it is the spelling Shadowrocket emits and
	// the one airports hand out. A user's real link --
	// socks5://…@host:443?security=tls -- was refused with "recognized but
	// unsupported", which reads as "this build cannot do TLS over socks5" and
	// is not true: mihomo's socks5 outbound has a tls field and this tree has
	// an interop test for it. The key was simply never registered, and only
	// this one spelling of it. Reported by the iOS lane 2026-08-28 from the
	// user's own subscription.
	"socks5": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "tls", "security", "udp", "allowInsecure",
		"allow_insecure", "insecure", "skip-cert-verify", "fingerprint", "hpkp",
	),
	"trojan": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "tls", "peer", "sni", "serverName",
		"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
		"fingerprint", "fp", "hpkp", "pcs", "pbk", "publicKey", "sid", "shortId", "security",
		"type", "proto", "network", "obfs", "obfsParam", "path", "host", "serviceName", "plugin",
	),
	// `udp` is on almost every airport ss link and was not here, so a real
	// subscription came back "recognized but unsupported" -- for a field
	// mihomo's ss outbound has. Registered and honoured, not merely tolerated:
	// a node that imports with udp silently off fails differently and later.
	"ss": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "udp-over-tcp", "uot", "plugin",
		"obfs", "obfsParam", "path", "client-fingerprint",
	),
	"snell": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "psk", "password", "version", "v",
		"udp", "reuse", "obfs", "obfs-mode", "obfsParam", "obfs-host", "peer", "sni", "plugin",
		"security", "alpn", "keepalive", "fingerprint", "hpkp", "pbk", "publicKey", "sid", "shortId",
	),
	"vless": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "uot", "padding", "fragment",
		"tls", "xtls", "peer", "sni", "serverName", "tlsServerName", "allowInsecure", "allow_insecure",
		"insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp", "pcs", "pbk",
		"publicKey", "sid", "shortId", "obfs", "obfsParam", "security", "packetEncoding", "type",
		"headerType", "host", "method", "path", "ed", "eh", "serviceName", "mode", "extra", "flow",
		"encryption",
	),
	"hysteria": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "auth", "peer", "sni", "serverName",
		"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "up", "upmbps",
		"down", "downmbps", "alpn", "obfs", "protocol", "fingerprint", "hpkp", "pinSHA256", "keepalive",
	),
	"hysteria2": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
		"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "up", "upmbps",
		"down", "downmbps", "alpn", "obfs", "obfs-password", "obfsParam", "fingerprint", "hpkp",
		"pinSHA256", "keepalive", "pbk", "publicKey", "sid", "shortId",
		// Port hopping: Shadowrocket spells it mport, mihomo spells it ports, and the
		// authority form is lifted into the same key before the URL is parsed.
		"mport", "ports", "hop-interval", "hopInterval",
		// The +realm spellings carry these; upstream reads them into realm-opts.
		"auth", "stun",
	),
	"tuic": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
		"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
		"congestion_control", "congestion-controller", "proto", "udp_relay_mode", "udp-relay-mode", "udp",
		"disable_sni", "fingerprint", "hpkp", "pinSHA256", "pbk", "publicKey", "sid", "shortId",
	),
	"wireguard": queryFieldSet(
		"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "publicKey", "public-key",
		"privateKey", "private-key", "ip", "presharedKey", "preSharedKey", "pre-shared-key", "password",
		"mtu", "keepalive", "persistent-keepalive", "dns", "reserved", "udp", "sni", "peer",
		"preshared-key",
	),
	"masque": queryFieldSet(
		"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "publicKey", "public-key",
		"privateKey", "private-key", "ip", "presharedKey", "preSharedKey", "pre-shared-key", "password",
		"peer", "sni", "serverName", "tlsServerName", "allowInsecure", "allow_insecure", "insecure",
		"skip-cert-verify", "uri", "mtu", "proto", "network", "dns", "keepalive", "reserved", "udp",
	),
	"ssh": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "user", "password", "private-key",
		"privateKey", "pk", "private-key-passphrase", "privateKeyPassphrase", "pp", "keepalive", "path",
	),
	"anytls": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
		"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
		"fingerprint", "fp", "hpkp", "udp", "keepalive", "pbk", "publicKey", "sid", "shortId",
	),
	"trusttunnel": queryFieldSet(
		"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "peer", "sni", "hostname",
		"allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "proto", "protocol",
		"alpn", "fingerprint", "fp", "client-fingerprint",
	),
	"mieru": queryFieldSet(
		"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "port", "protocol", "proto",
		"transport", "multiplexing", "handshake-mode", "traffic-pattern", "peer", "sni", "allowInsecure",
		"allow_insecure", "insecure", "skip-cert-verify", "alpn", "udp", "mtu", "fingerprint", "hpkp", "pbk",
		"publicKey", "sid", "shortId",
	),
}

func queryFieldSet(fields ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result
}

var proxyImportURLPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*)://`)

// ProxyImportCapabilitiesForIOS exposes the Core-owned registry to Apple UI.
// The client may use this snapshot for routing and copy, but must not maintain a
// second scheme set.
func ProxyImportCapabilitiesForIOS() *StringBox {
	encoded, _ := json.Marshal(proxyImportCapabilitiesDocument{
		Schemes:  proxyImportCapabilities,
		Contexts: []string{"singleNode", "nodeBundle", "subscriptionBody", "configuration"},
	})
	return WrapString(string(encoded))
}

// A guessed context is reported the same way a dropped field is: the caller
// gets what it asked for, and is told what part of the request was not taken at
// face value.
func addProxyImportContextNotice(report *proxyImportReport, notice string) {
	if notice == "" {
		return
	}
	report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
		Code: "fieldNotHonoured", Message: "hako: proxy field " + notice,
	})
}

// InspectProxyPayloadForIOS reads a pasted payload and reports what became a
// node and what did not, so a person can see it before anything is saved.
//
// Two outcomes, not three. A record either produced a proxy or it was skipped
// with the reason; `notHonoured` is not a third one, it names fields that did
// not survive on nodes that did. The doc comment that stood here described a
// "recognized but unsupported" bucket, which stopped existing on 2026-08-28 --
// and it had come adrift from this function entirely, sitting above an
// unexported helper where nothing rendered it.
func InspectProxyPayloadForIOS(payload []byte, context string) (*StringBox, error) {
	if len(payload) == 0 {
		return nil, bridgeSafeError(fmt.Errorf("hako: proxy payload is empty"))
	}
	if len(payload) > maximumProviderResourceBytes {
		return nil, bridgeSafeError(fmt.Errorf("hako: proxy payload is %d bytes, over the %d-byte limit",
			len(payload), maximumProviderResourceBytes))
	}
	// An unknown context is guessed at, not refused. What the person pasted is a
	// fact only the content knows, and this parameter asks the call site to
	// declare it -- so a wrong guess at the call site used to lose the whole
	// payload, including the part that parsed cleanly. The parser will decide
	// this for itself in a later release; until then a bad value costs a notice,
	// not the import.
	//
	// nodeBundle is the guess because it is the one that constrains nothing:
	// `configuration` sends the payload down the container path and `singleNode`
	// refuses more than one record, while nodeBundle takes whatever arrives.
	var contextNotice string
	switch context {
	case "singleNode", "nodeBundle", "subscriptionBody", "configuration":
	default:
		contextNotice = "import.context=" + context + ": not a context this build knows, so the payload was read as a bundle of nodes"
		context = "nodeBundle"
	}

	if report, matched, err := inspectProxyContainer(payload, context); matched {
		if err != nil {
			return nil, bridgeSafeError(err)
		}
		addProxyImportContextNotice(&report, contextNotice)
		bridgedValue0, bridgedErr := encodeProxyImportReport(report)
		return bridgedValue0, bridgeSafeError(bridgedErr)
	}
	// Upstream decodes the whole body before it looks at anything at all
	// (common/convert/converter.go), so a subscription that base64s its body
	// carries the same proxies as one that does not -- including when what it
	// wrapped is a container rather than a list of links. Base64 is just a fifth
	// spelling of the container, and a spelling is not a fact about the contents
	// . The undecoded payload is tried first, so this only ever runs on
	// something no detector recognised as it stands.
	if decoded, decodeErr := convert.TryDecodeBase64(string(bytes.TrimSpace(payload))); decodeErr == nil {
		if report, matched, containerErr := inspectProxyContainer(decoded, context); matched {
			if containerErr != nil {
				return nil, bridgeSafeError(containerErr)
			}
			addProxyImportContextNotice(&report, contextNotice)
			bridgedValue0, bridgedErr := encodeProxyImportReport(report)
			return bridgedValue0, bridgeSafeError(bridgedErr)
		}
	}
	if context == "configuration" {
		return nil, bridgeSafeError(fmt.Errorf("hako: configuration payload is not a recognized configuration container"))
	}

	text := string(payload)
	format := "share-links"
	if !proxyImportURLPattern.MatchString(text) {
		decoded, err := convert.TryDecodeBase64(strings.TrimSpace(text))
		if err == nil && proxyImportURLPattern.Match(decoded) {
			text = string(decoded)
			format = "base64-share-links"
		}
	}
	records := extractProxyImportRecords(text)
	if len(records) == 0 {
		return nil, bridgeSafeError(fmt.Errorf("hako: proxy payload format is unknown"))
	}
	if context == "singleNode" && len(records) != 1 {
		return nil, bridgeSafeError(fmt.Errorf("hako: single-node import contains %d records", len(records)))
	}

	capabilities := make(map[string]proxyImportCapability, len(proxyImportCapabilities))
	for _, capability := range proxyImportCapabilities {
		capabilities[capability.Scheme] = capability
	}
	report := proxyImportReport{
		Format:      format,
		Context:     context,
		Proxies:     make([]map[string]any, 0, len(records)),
		Skipped:     make([]proxyImportIssue, 0),
		NotHonoured: make([]proxyImportIssue, 0),
	}
	seenNames := make(map[string]int)
	for index, record := range records {
		scheme := strings.ToLower(record.scheme)
		capability, known := capabilities[scheme]
		if !known {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "unknownScheme",
				Message: fmt.Sprintf("proxy scheme %q is not recognized", scheme),
			})
			continue
		}
		if capability.Status != proxyImportSupported {
			code := capability.Status
			if code == proxyImportWrapper {
				code = "subscriptionWrapper"
			}
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: code,
				Message: fmt.Sprintf("proxy scheme %q is recognized but is not constructible by this importer", scheme),
			})
			continue
		}
		// The notices cannot be filed yet. Each one names a node, and the node
		// does not have its final name until makeProxyImportNameUnique has run
		// below -- two links called "HK" become "HK" and "HK-01", and a notice
		// stamped with the name from the link would send both to the first one.
		// If the record never becomes a node at all, they ride with the skip
		// instead.
		proxies, notHonoured, err := parseProxyShareLink(record.text, capability)
		pending := make([]string, 0, len(notHonoured))
		for _, notice := range notHonoured {
			pending = append(pending, "hako: proxy field "+notice)
		}
		skip := func(issue proxyImportIssue) {
			issue.AlsoNotHonoured = pending
			report.Skipped = append(report.Skipped, issue)
			pending = nil
		}
		if err != nil {
			var unsupported *proxyImportUnsupportedFieldError
			if errors.As(err, &unsupported) {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "recognizedUnsupportedField", Message: err.Error(),
				})
				continue
			}
			skip(proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "malformedRecord", Message: err.Error(),
			})
			continue
		}
		for _, proxy := range proxies {
			if validationErr := validateProxyImportRequiredFields(proxy); validationErr != nil {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "malformedRecord", Message: validationErr.Error(),
				})
				continue
			}
			outbound, parseErr := adapter.ParseProxy(proxy)
			if parseErr != nil {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "coreRejected", Message: parseErr.Error(),
				})
				continue
			}
			if closeErr := outbound.Close(); closeErr != nil {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "coreCloseFailed", Message: closeErr.Error(),
				})
				continue
			}
			report.Identities = append(report.Identities, proxyImportIdentity(proxy))
			makeProxyImportNameUnique(proxy, seenNames)
			name, _ := proxy["name"].(string)
			for _, notice := range pending {
				report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset,
					Code: "fieldNotHonoured", Message: notice, Proxy: name,
				})
			}
			pending = nil
			report.Proxies = append(report.Proxies, proxy)
		}
		// A record that produced neither a node nor a skip leaves its notices
		// with nowhere to go. Filing them under an empty name would put a notice
		// in the report that points at no node in it.
		for _, notice := range pending {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset,
				Code: "fieldNotHonoured", Message: notice,
			})
		}
		pending = nil
	}
	// singleNode does not collapse the outcome into one sentence. The caller
	// decides whether one constructible proxy came back; the reasons the others
	// did not are already in the report, and they are the only actionable part.
	addProxyImportContextNotice(&report, contextNotice)
	bridgedValue0, bridgedErr := encodeProxyImportReport(report)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func encodeProxyImportReport(report proxyImportReport) (*StringBox, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("hako: encode proxy import report: %w", err)
	}
	return WrapString(string(encoded)), nil
}

// validateProxyImportRequiredFields enforces the authentication contract before
// asking the Core to construct an outbound. Some upstream constructors accept
// empty credentials and fail only when a connection is attempted; accepting
// such a record here would turn an import success into a guaranteed runtime
// failure. Keep this validation format-agnostic so URI, JSON, YAML and INI
// imports receive the same result.
func validateProxyImportRequiredFields(proxy map[string]any) error {
	kind := strings.ToLower(strings.TrimSpace(anyString(proxy["type"])))
	require := func(fields ...string) error {
		for _, field := range fields {
			if strings.TrimSpace(anyString(proxy[field])) == "" {
				return fmt.Errorf("hako: %s proxy requires %s", kind, field)
			}
		}
		return nil
	}

	switch kind {
	case "vmess", "vless":
		return require("uuid")
	case "trojan", "anytls":
		return require("password")
	case "ss":
		return require("cipher", "password")
	case "ssr":
		return require("cipher", "password", "protocol", "obfs")
	case "snell":
		return require("psk")
	case "tuic":
		if strings.TrimSpace(anyString(proxy["token"])) != "" {
			return nil
		}
		if strings.TrimSpace(anyString(proxy["uuid"])) == "" || strings.TrimSpace(anyString(proxy["password"])) == "" {
			return fmt.Errorf("hako: tuic proxy requires token or both uuid and password")
		}
	case "wireguard":
		if err := require("private-key", "public-key"); err != nil {
			return err
		}
		if strings.TrimSpace(anyString(proxy["ip"])) == "" && strings.TrimSpace(anyString(proxy["ipv6"])) == "" {
			return fmt.Errorf("hako: wireguard proxy requires ip or ipv6")
		}
	case "ssh":
		if err := require("username"); err != nil {
			return err
		}
		if strings.TrimSpace(anyString(proxy["password"])) == "" && strings.TrimSpace(anyString(proxy["private-key"])) == "" {
			return fmt.Errorf("hako: ssh proxy requires password or private-key")
		}
	case "trusttunnel", "mieru":
		return require("username", "password")
	}
	return nil
}

func inspectProxyContainer(payload []byte, context string) (proxyImportReport, bool, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return proxyImportReport{}, false, nil
	}
	text := string(trimmed)
	var (
		format  string
		proxies []map[string]any
		err     error
		matched bool
		// Records a container-format parser could not read. They are records, not
		// a reason to throw the document away, so they travel here rather than in
		// the error return.
		containerSkipped []proxyImportIssue
		// The fields each record named that this build does not map, parallel to
		// proxies: containerNotHonoured[i] belongs to proxies[i]. Only the JSON
		// dialects and SSD have whitelists, so only they produce any; the other
		// parsers leave it nil, and a nil entry is no notices.
		containerNotHonoured [][]string
	)
	switch {
	case looksLikeMihomoYAML(text):
		matched = true
		format = "mihomo-yaml"
		proxies, err = parseMihomoProxyDocument(trimmed)
	case trimmed[0] == '-':
		if parsed, ok := parseBareMihomoProxySequence(trimmed); ok {
			matched = true
			format = "mihomo-yaml"
			proxies = parsed
		}
	case strings.Contains(text, "[Proxy]"):
		matched = true
		format = "surge"
		var surgeSkipped []proxyImportIssue
		proxies, surgeSkipped, err = parseSurgeProxySection(text)
		containerSkipped = append(containerSkipped, surgeSkipped...)
	case strings.Contains(text, "[Interface]") && strings.Contains(text, "[Peer]"):
		matched = true
		format = "wireguard-ini"
		var proxy map[string]any
		proxy, err = parseWireGuardINI(text)
		if err == nil {
			proxies = []map[string]any{proxy}
		}
	case trimmed[0] == '{' || trimmed[0] == '[':
		matched = true
		var jsonSkipped []proxyImportIssue
		format, proxies, containerNotHonoured, jsonSkipped, err = parseJSONProxyContainer(trimmed)
		containerSkipped = append(containerSkipped, jsonSkipped...)
	case strings.HasPrefix(strings.ToLower(text), "ssd://"):
		matched = true
		format = "ssd"
		var ssdSkipped []proxyImportIssue
		proxies, containerNotHonoured, ssdSkipped, err = parseSSDSubscription(text)
		containerSkipped = append(containerSkipped, ssdSkipped...)
	}
	shape := classifyProxyImportDocument(trimmed)
	if !matched {
		// A configuration whose nodes all live in `proxy-providers`, and one that
		// only carries rules, are both valid and both hold no inline proxies. Left
		// to the detectors above they came back as `format is unknown` -- the same
		// answer an HTML login page gets -- so a caller could not tell "valid, no
		// nodes here" from "not a configuration". It ends up rebuilding mihomo's
		// vocabulary to tell them apart, which is the kernel's to own.
		if shape != nil && shape.IsConfiguration {
			return proxyImportReport{
				Format: mihomoDocumentFormat(trimmed), Context: context,
				Proxies:      make([]map[string]any, 0),
				Skipped:      make([]proxyImportIssue, 0),
				NotHonoured:  make([]proxyImportIssue, 0),
				PayloadShape: shape,
			}, true, nil
		}
		return proxyImportReport{}, false, nil
	}
	if err != nil {
		return proxyImportReport{}, true, fmt.Errorf("hako: parse %s proxy payload: %w", format, err)
	}
	if len(proxies) == 0 && len(containerSkipped) > 0 {
		// Every record was skipped. That is a report, not a failure to read the
		// document: the person gets the reasons, one per record, instead of one
		// sentence saying the payload had no proxies in it.
		return proxyImportReport{
			Format: format, Context: context,
			Proxies:      make([]map[string]any, 0),
			Skipped:      containerSkipped,
			NotHonoured:  make([]proxyImportIssue, 0),
			Identities:   make([]string, 0),
			PayloadShape: shape,
		}, true, nil
	}
	if len(proxies) == 0 {
		if shape != nil && shape.IsConfiguration {
			return proxyImportReport{
				Format: format, Context: context,
				Proxies:      make([]map[string]any, 0),
				Skipped:      make([]proxyImportIssue, 0),
				NotHonoured:  make([]proxyImportIssue, 0),
				PayloadShape: shape,
			}, true, nil
		}
		return proxyImportReport{}, true, fmt.Errorf("hako: %s proxy payload contains no proxies", format)
	}
	report := proxyImportReport{
		Format: format, Context: context,
		Proxies: make([]map[string]any, 0, len(proxies)),
		// The records the format's own parser could not read come first, because
		// they were skipped before any of the rest existed.
		Skipped:     append(make([]proxyImportIssue, 0, len(containerSkipped)), containerSkipped...),
		NotHonoured: make([]proxyImportIssue, 0),
		Identities:  make([]string, 0, len(proxies)),
	}
	seenNames := make(map[string]int)
	for index, proxy := range proxies {
		scheme, _ := proxy["type"].(string)
		// What this record named that we do not map. Filed under the node once
		// the node has its final name; carried by the skip when there is no
		// node -- the same shape the share-link door gives its notices.
		var pending []string
		if index < len(containerNotHonoured) {
			pending = proxyImportNoticeMessages(containerNotHonoured[index])
		}
		skip := func(code string, reason error) {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Code: code, Message: reason.Error(),
				AlsoNotHonoured: pending,
			})
		}
		if validationErr := validateProxyImportRequiredFields(proxy); validationErr != nil {
			skip("malformedRecord", validationErr)
			continue
		}
		outbound, parseErr := adapter.ParseProxy(proxy)
		if parseErr != nil {
			skip("coreRejected", parseErr)
			continue
		}
		if closeErr := outbound.Close(); closeErr != nil {
			skip("coreCloseFailed", closeErr)
			continue
		}
		report.Identities = append(report.Identities, proxyImportIdentity(proxy))
		makeProxyImportNameUnique(proxy, seenNames)
		report.Proxies = append(report.Proxies, proxy)
		name, _ := proxy["name"].(string)
		for _, message := range pending {
			report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
				Index: index, Scheme: scheme, Code: "fieldNotHonoured", Message: message, Proxy: name,
			})
		}
	}
	report.PayloadShape = shape
	return report, true, nil
}

// classifyProxyImportDocument decodes a top-level mapping and says what it is.
// YAML is a superset of JSON, so one decode covers both spellings.
func classifyProxyImportDocument(payload []byte) *proxyImportPayloadShape {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil || len(document) == 0 {
		return nil
	}
	return describeProxyImportPayloadShape(document)
}

func mihomoDocumentFormat(payload []byte) string {
	if trimmed := bytes.TrimSpace(payload); len(trimmed) > 0 && trimmed[0] == '{' {
		return "mihomo-json"
	}
	return "mihomo-yaml"
}

var mihomoProxyKeyPattern = regexp.MustCompile(`(?m)^[ \t]*(?:proxies|Proxy|proxy-providers)[ \t]*:`)

func looksLikeMihomoYAML(text string) bool {
	return mihomoProxyKeyPattern.MatchString(text)
}

func parseMihomoProxyDocument(payload []byte) ([]map[string]any, error) {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, err
	}
	raw, ok := document["proxies"]
	if !ok {
		raw = document["Proxy"]
	}
	if raw == nil {
		// A configuration whose nodes all come from `proxy-providers` carries no
		// `proxies:` key at all, and it is not malformed for that. The caller
		// decides what an empty list means; refusing it here made a valid
		// subscription look broken.
		return []map[string]any{}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proxies must be a sequence")
	}
	proxies := make([]map[string]any, 0, len(items))
	for index, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %d must be a mapping", index)
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

// parseBareMihomoProxySequence accepts a YAML sequence of proxies pasted without
// the `proxies:` key that would wrap them inside a full configuration. An excerpt
// holds the same proxies as the document it was cut from, so it imports the same
// way; requiring the wrapper would make the paste's shape a fact about its
// contents. It reports false for anything it is not certain about, leaving the
// payload to the share-link reader.
func parseBareMihomoProxySequence(payload []byte) ([]map[string]any, bool) {
	var items []any
	if err := yaml.Unmarshal(payload, &items); err != nil || len(items) == 0 {
		return nil, false
	}
	proxies := make([]map[string]any, 0, len(items))
	for _, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok || !jsonObjectIsCanonicalMihomoProxy(proxy) {
			return nil, false
		}
		proxies = append(proxies, proxy)
	}
	return proxies, true
}

// One unreadable line does not cost the other two hundred.
//
// Every per-line failure here used to return an error that reached the caller
// as "parse surge proxy payload: ..." with no report at all, so a person whose
// configuration carried one line this build could not read got nothing back --
// not the nodes that were fine, not the reason for the one that was not. The
// reader's rule is parse what parses, skip what does not, and say what was
// skipped, and a container format is where that matters most: share links
// arrive a few at a time, a configuration arrives with hundreds of nodes in it.
//
// The returned error is now reserved for the document as a whole. A line is a
// record like any other, and it is skipped with its line number.
func parseSurgeProxySection(text string) ([]map[string]any, []proxyImportIssue, error) {
	inProxySection := false
	var proxies []map[string]any
	skipped := make([]proxyImportIssue, 0)
	skip := func(number int, line, message string) {
		skipped = append(skipped, proxyImportIssue{
			Index: len(proxies) + len(skipped), Scheme: "surge", Line: number,
			Code: "malformedRecord", Message: message,
		})
		_ = line
	}
	for number, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inProxySection = strings.EqualFold(line, "[Proxy]")
			continue
		}
		if !inProxySection {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			skip(number+1, line, fmt.Sprintf("invalid [Proxy] line %q", line))
			continue
		}
		reader := csv.NewReader(strings.NewReader(value))
		reader.TrimLeadingSpace = true
		fields, err := reader.Read()
		if err != nil || len(fields) < 3 {
			skip(number+1, line, fmt.Sprintf("invalid [Proxy] value for %q", strings.TrimSpace(name)))
			continue
		}
		proxy, err := surgeProxyMapping(strings.TrimSpace(name), fields)
		if err != nil {
			skip(number+1, line, err.Error())
			continue
		}
		proxies = append(proxies, proxy)
	}
	return proxies, skipped, nil
}

func surgeProxyMapping(name string, fields []string) (map[string]any, error) {
	kind := strings.ToLower(strings.TrimSpace(fields[0]))
	server := strings.TrimSpace(fields[1])
	port, err := strconv.Atoi(strings.TrimSpace(fields[2]))
	if name == "" || server == "" || err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid proxy line %q", name)
	}
	options := make(map[string]string)
	for _, field := range fields[3:] {
		trimmed := strings.TrimSpace(field)
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			if trimmed != "" {
				return nil, unsupportedProxyImportField("surge."+kind+"."+trimmed, "bare option has no mapped semantics")
			}
			continue
		}
		options[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	allowed := queryFieldSet("tfo", "fast-open", "udp", "udp-relay")
	switch kind {
	case "ss", "shadowsocks":
		mergeFieldSet(allowed, "encrypt-method", "method", "cipher", "password")
	case "trojan":
		mergeFieldSet(allowed, "password", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure")
	case "vmess":
		mergeFieldSet(allowed, "username", "uuid", "tls", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure")
	case "http", "https", "socks5", "socks":
		mergeFieldSet(allowed, "username", "password", "tls", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure")
	case "snell":
		mergeFieldSet(allowed, "psk", "version")
	}
	if err := validateStringMapKeys("surge."+kind, options, allowed); err != nil {
		return nil, err
	}
	proxy := map[string]any{"name": name, "server": server, "port": port}
	switch kind {
	case "ss", "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = firstStringMapValue(options, "encrypt-method", "method", "cipher")
		proxy["password"] = options["password"]
		proxy["udp"] = true
	case "trojan":
		proxy["type"] = "trojan"
		proxy["password"] = options["password"]
		proxy["udp"] = true
	case "vmess":
		proxy["type"] = "vmess"
		proxy["uuid"] = firstStringMapValue(options, "username", "uuid")
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
	case "http", "https":
		proxy["type"] = "http"
		proxy["username"] = options["username"]
		proxy["password"] = options["password"]
		proxy["tls"] = kind == "https" || stringMapBoolean(options, "tls")
	case "socks5", "socks":
		proxy["type"] = "socks5"
		proxy["username"] = options["username"]
		proxy["password"] = options["password"]
		proxy["udp"] = stringMapBoolean(options, "udp-relay", "udp")
	case "snell":
		proxy["type"] = "snell"
		proxy["psk"] = options["psk"]
		if version, parseErr := strconv.Atoi(options["version"]); parseErr == nil && version != 0 {
			proxy["version"] = version
		}
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", kind)
	}
	if sni := firstStringMapValue(options, "sni", "peer", "server-name"); sni != "" {
		if kind == "vmess" {
			proxy["servername"] = sni
		} else {
			proxy["sni"] = sni
		}
	}
	if stringMapBoolean(options, "skip-cert-verify", "allow-insecure") {
		proxy["skip-cert-verify"] = true
	}
	if stringMapBoolean(options, "tfo", "fast-open") {
		proxy["tfo"] = true
	}
	if stringMapBoolean(options, "udp", "udp-relay") {
		proxy["udp"] = true
	}
	return proxy, nil
}

func firstStringMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

func stringMapBoolean(values map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(values[key]) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func validateStringMapKeys(prefix string, values map[string]string, allowed map[string]struct{}) error {
	for key, value := range values {
		if _, ok := allowed[key]; ok || strings.TrimSpace(value) == "" {
			continue
		}
		return unsupportedProxyImportField(prefix+"."+key, "container field is not mapped by this importer build")
	}
	return nil
}

// The skipped records travel beside the proxies rather than inside the error.
// A JSON container is a document with many records in it, and an outbound this
// build cannot read is one of them -- returning it as the function's error made
// it the whole document's verdict.
// parseJSONProxyContainer returns the dialect, the nodes, the not-mapped
// notices parallel to the nodes (nil for the canonical mihomo shape, which has
// no whitelist), and the records that were skipped.
func parseJSONProxyContainer(payload []byte) (string, []map[string]any, [][]string, []proxyImportIssue, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "json", nil, nil, nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "json", nil, nil, nil, err
	}
	if array, ok := value.([]any); ok {
		proxies, notHonoured, nested, skipped, err := parseJSONArrayProxyContainers(array)
		if nested {
			return "mixed-proxy-json", proxies, notHonoured, skipped, err
		}
		return "proxy-json", proxies, notHonoured, skipped, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "json", nil, nil, nil, fmt.Errorf("top level must be an object or array")
	}
	if raw, ok := object["proxies"].([]any); ok {
		proxies, skipped := canonicalJSONProxyArray(raw)
		return "mihomo-json", proxies, nil, skipped, nil
	}
	if raw, ok := object["servers"].([]any); ok {
		proxies, notHonoured, skipped := parseJSONServerArray(raw, object)
		format := "shadowrocket-json"
		if len(raw) > 0 {
			if first, ok := raw[0].(map[string]any); ok && first["server_port"] != nil {
				format = "sip008-json"
			}
		}
		return format, proxies, notHonoured, skipped, nil
	}
	if raw, ok := object["outbounds"].([]any); ok {
		format := "sing-box-json"
		if len(raw) > 0 {
			if first, ok := raw[0].(map[string]any); ok && first["protocol"] != nil {
				format = "v2ray-json"
			}
		}
		proxies, notHonoured, skipped, err := parseJSONOutbounds(raw, format)
		return format, proxies, notHonoured, skipped, err
	}
	if shape := describeProxyImportPayloadShape(object); shape != nil && !shape.IsConfiguration {
		return "json", nil, nil, nil, fmt.Errorf(
			"JSON is not a mihomo configuration: none of its %d top level key(s) is one the kernel declares (%s)",
			len(shape.UnrecognizedKeys), strings.Join(shape.UnrecognizedKeys, ", "))
	}
	return "json", nil, nil, nil, fmt.Errorf("JSON does not contain proxies or servers")
}

func parseJSONArrayProxyContainers(items []any) ([]map[string]any, [][]string, bool, []proxyImportIssue, error) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	nestedSkipped := make([]proxyImportIssue, 0)
	nested := false
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, nil, nested, nil, fmt.Errorf("server %d must be an object", index)
		}
		var (
			parsed  []map[string]any
			notices [][]string
			err     error
		)
		switch {
		case object["proxies"] != nil:
			nested = true
			raw, ok := object["proxies"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d proxies must be an array", index)
			}
			var proxySkipped []proxyImportIssue
			parsed, proxySkipped = canonicalJSONProxyArray(raw)
			nestedSkipped = append(nestedSkipped, proxySkipped...)
		case object["servers"] != nil:
			nested = true
			raw, ok := object["servers"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d servers must be an array", index)
			}
			var serverSkipped []proxyImportIssue
			parsed, notices, serverSkipped = parseJSONServerArray(raw, object)
			nestedSkipped = append(nestedSkipped, serverSkipped...)
		case object["outbounds"] != nil:
			nested = true
			raw, ok := object["outbounds"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d outbounds must be an array", index)
			}
			format := "sing-box-json"
			if len(raw) > 0 {
				if first, ok := raw[0].(map[string]any); ok && first["protocol"] != nil {
					format = "v2ray-json"
				}
			}
			var outboundSkipped []proxyImportIssue
			parsed, notices, outboundSkipped, err = parseJSONOutbounds(raw, format)
			nestedSkipped = append(nestedSkipped, outboundSkipped...)
		case jsonObjectIsCanonicalMihomoProxy(object):
			// One object, already known to be one, so nothing is skipped.
			parsed, _ = canonicalJSONProxyArray([]any{object})
		default:
			var (
				proxy      map[string]any
				serverNote []string
			)
			proxy, serverNote, err = jsonServerMapping(object, nil)
			if err == nil {
				parsed = []map[string]any{proxy}
				notices = [][]string{serverNote}
			}
		}
		if err != nil {
			// One item of a JSON array is a record. It used to be the array's
			// verdict.
			nestedSkipped = append(nestedSkipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("JSON item %d: %v", index, err),
			})
			continue
		}
		proxies = append(proxies, parsed...)
		notHonoured = append(notHonoured, paddedNotices(notices, len(parsed))...)
	}
	return proxies, notHonoured, nested, nestedSkipped, nil
}

// paddedNotices keeps a notice list parallel to the nodes it belongs to when
// the parser that produced the nodes had no notices to give (the canonical
// mihomo shapes have no whitelist, so they have nothing to name).
func paddedNotices(notices [][]string, count int) [][]string {
	if len(notices) == count {
		return notices
	}
	return make([][]string, count)
}

// parseJSONOutbounds returns the nodes, the not-mapped notices parallel to
// them (see parseJSONServerArray), and the outbounds that were skipped.
func parseJSONOutbounds(items []any, format string) ([]map[string]any, [][]string, []proxyImportIssue, error) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	skipped := make([]proxyImportIssue, 0)
	for index, item := range items {
		outbound, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("outbound %d must be an object", index),
			})
			continue
		}
		var (
			proxy   map[string]any
			notices []string
			err     error
			skip    bool
		)
		if format == "v2ray-json" {
			proxy, skip, notices, err = v2rayOutboundMapping(outbound)
		} else {
			proxy, skip, notices, err = singBoxOutboundMapping(outbound)
		}
		if err != nil {
			// Same rule as the surge section: an outbound this build cannot read
			// is one record, and the other outbounds in the file are not its
			// fault. This used to abort the document with `outbound 7: ...` and
			// return no report, so a person whose sing-box file carried one field
			// we do not map lost every node in it. The fields it named that we
			// do not map ride with the skip: there is no node to file them under.
			skipped = append(skipped, proxyImportIssue{
				Index: index, Scheme: anyString(outbound["type"]),
				Code: "malformedRecord", Message: err.Error(),
				AlsoNotHonoured: proxyImportNoticeMessages(notices),
			})
			continue
		}
		if !skip {
			proxies = append(proxies, proxy)
			notHonoured = append(notHonoured, notices)
		}
	}
	return proxies, notHonoured, skipped, nil
}

// singBoxOutboundMapping reads one sing-box outbound. The third result is the
// fields the outbound named that this build did not map; it comes back with an
// error too, so the notices ride with the skip when the record produces no
// node.
func singBoxOutboundMapping(outbound map[string]any) (map[string]any, bool, []string, error) {
	kind := strings.ToLower(anyString(outbound["type"]))
	switch kind {
	case "direct", "block", "dns", "selector", "urltest":
		return nil, true, nil, nil
	}
	allowed := queryFieldSet("type", "tag", "server", "server_port", "tls", "transport")
	switch kind {
	case "vless":
		mergeFieldSet(allowed, "uuid", "flow")
	case "vmess":
		mergeFieldSet(allowed, "uuid", "alter_id", "security", "cipher")
	case "trojan", "hysteria2", "anytls":
		mergeFieldSet(allowed, "password")
	case "hysteria":
		mergeFieldSet(allowed, "auth_str", "auth", "up", "up_mbps", "down", "down_mbps")
	case "shadowsocks":
		mergeFieldSet(allowed, "method", "password")
	case "socks", "socks5", "http":
		mergeFieldSet(allowed, "username", "password")
	case "ssh":
		mergeFieldSet(allowed, "user", "password", "private_key")
	}
	notHonoured := unmappedObjectKeys("sing-box.outbound", outbound, allowed)
	server := anyString(outbound["server"])
	port, ok := anyInt(outbound["server_port"])
	if server == "" || !ok || port < 1 || port > 65535 {
		return nil, false, notHonoured, fmt.Errorf("%s outbound is missing server or server_port", kind)
	}
	name := anyString(outbound["tag"])
	if name == "" {
		name = server
	}
	proxy := map[string]any{"name": name, "type": kind, "server": server, "port": port}
	switch kind {
	case "vless":
		proxy["uuid"] = anyString(outbound["uuid"])
		if flow := anyString(outbound["flow"]); flow != "" {
			proxy["flow"] = flow
		}
	case "vmess":
		proxy["uuid"] = anyString(outbound["uuid"])
		proxy["alterId"], _ = anyInt(outbound["alter_id"])
		proxy["cipher"] = firstAnyString(outbound, "security", "cipher")
		if proxy["cipher"] == "" {
			proxy["cipher"] = "auto"
		}
	case "trojan", "hysteria2", "anytls":
		proxy["password"] = anyString(outbound["password"])
	case "hysteria":
		proxy["auth-str"] = firstAnyString(outbound, "auth_str", "auth")
		proxy["up"] = firstAnyString(outbound, "up", "up_mbps")
		proxy["down"] = firstAnyString(outbound, "down", "down_mbps")
	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = anyString(outbound["method"])
		proxy["password"] = anyString(outbound["password"])
	case "socks", "socks5":
		proxy["type"] = "socks5"
		proxy["username"] = anyString(outbound["username"])
		proxy["password"] = anyString(outbound["password"])
	case "http":
		proxy["username"] = anyString(outbound["username"])
		proxy["password"] = anyString(outbound["password"])
	case "ssh":
		proxy["username"] = anyString(outbound["user"])
		proxy["password"] = anyString(outbound["password"])
		if privateKey := anyString(outbound["private_key"]); privateKey != "" {
			proxy["private-key"] = privateKey
		}
	default:
		return nil, false, notHonoured, fmt.Errorf("unsupported outbound type %q in this configuration dialect", kind)
	}
	tlsNotHonoured, err := applySingBoxTLS(proxy, outbound["tls"])
	notHonoured = append(notHonoured, tlsNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	transportNotHonoured, err := applySingBoxTransport(proxy, outbound["transport"])
	notHonoured = append(notHonoured, transportNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	return proxy, false, notHonoured, nil
}

func firstAnyString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := anyString(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func mergeFieldSet(fields map[string]struct{}, additions ...string) {
	for _, field := range additions {
		fields[field] = struct{}{}
	}
}

// unmappedObjectKeys names the keys of a JSON object this build has nowhere to
// put, as "<prefix>.<key>: not mapped by this importer build", sorted so a
// report reads the same on every run.
//
// It refused until 2026-09-02. The first key it did not list threw the whole
// record away as `recognized but unsupported`, which was wrong on both counts:
// nobody had recognised the key, and the node connects without it -- the
// key asked for something this build cannot give, which is what the notice
// says, not a reason to withhold the node.
// A person's subscription found it -- seven vmess nodes, each carrying
// `"class": 0`, none of them imported, all seven built by upstream, which
// decodes the same body and reads only the keys it knows. The query keys had
// stopped refusing on 2026-08-28 for exactly this reason; the twenty-two JSON
// whitelists calling this function had not, because the parity gate that
// forced that change cannot see them -- mihomo does not read sing-box or v2ray
// files, so there is nothing to measure them against. The reader's ruling:
// one rule for every key this importer reads. The node arrives; the key is
// named, under the node, as not honoured. Louder than upstream, no longer
// stricter.
//
// Empty values do not count. An exporter that writes `"flow": ""` on every
// node is not naming a field. A number does count -- `"class": 0` is a value,
// and it is the one that was reported.
func unmappedObjectKeys(prefix string, object map[string]any, allowed map[string]struct{}) []string {
	var notices []string
	for key, value := range object {
		if _, ok := allowed[key]; ok || isAbsentImportValue(value) {
			continue
		}
		notices = append(notices, unmappedProxyImportFieldNotice(prefix+"."+key))
	}
	sort.Strings(notices)
	return notices
}

// unmappedProxyImportFieldNotice is the one sentence for a field nobody maps,
// so a query key, an SSR body key and a JSON body key all say it the same way.
func unmappedProxyImportFieldNotice(path string) string {
	return path + ": not mapped by this importer build"
}

// proxyImportNoticeMessages turns the raw notices a parser collected into the
// messages the report carries, spelled the way the share-link door spells them.
func proxyImportNoticeMessages(notices []string) []string {
	if len(notices) == 0 {
		return nil
	}
	messages := make([]string, 0, len(notices))
	for _, notice := range notices {
		messages = append(messages, "hako: proxy field "+notice)
	}
	return messages
}

func importObject(prefix string, raw any) (map[string]any, bool, error) {
	if isEmptyImportValue(raw) {
		return nil, false, nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, false, unsupportedProxyImportField(prefix, "JSON child must be an object")
	}
	return object, true, nil
}

// isAbsentImportValue is the naming predicate: a key whose value is nothing
// -- nil, blank, [] or {} -- asked for nothing and is not named. A `false` is
// not nothing. `"verify_cert": false` asks for a node that does not check the
// certificate, and this build has nowhere to put that; building a checking
// node and saying so is the ruling, building one in silence is not. The
// mapping predicate below still folds `false` away, because for the keys it
// reads a `false` means "leave the default", which is exactly what happens.
func isAbsentImportValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	}
	return false
}

func isEmptyImportValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case bool:
		return !typed
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	}
	return false
}

func hasNonemptyObjectValue(object map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, exists := object[key]; exists && !isEmptyImportValue(value) {
			return true
		}
	}
	return false
}

func applySingBoxTLS(proxy map[string]any, raw any) ([]string, error) {
	tls, present, err := importObject("sing-box.outbound.tls", raw)
	if err != nil || !present {
		return nil, err
	}
	notHonoured := unmappedObjectKeys(
		"sing-box.outbound.tls", tls,
		queryFieldSet("enabled", "server_name", "insecure", "alpn", "utls", "reality"),
	)
	if !anyBool(tls["enabled"]) {
		if hasNonemptyObjectValue(tls, "server_name", "insecure", "alpn", "utls", "reality") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.enabled", "TLS children are set while TLS is disabled")
		}
		return notHonoured, nil
	}
	proxy["tls"] = true
	if serverName := anyString(tls["server_name"]); serverName != "" {
		if proxy["type"] == "vless" || proxy["type"] == "vmess" {
			proxy["servername"] = serverName
		} else {
			proxy["sni"] = serverName
		}
	}
	if anyBool(tls["insecure"]) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := anyStringSlice(tls["alpn"]); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if utls, exists, objectErr := importObject("sing-box.outbound.tls.utls", tls["utls"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		notHonoured = append(notHonoured, unmappedObjectKeys("sing-box.outbound.tls.utls", utls, queryFieldSet("enabled", "fingerprint"))...)
		if anyBool(utls["enabled"]) {
			if fingerprint := anyString(utls["fingerprint"]); fingerprint != "" {
				proxy["client-fingerprint"] = fingerprint
			}
		} else if hasNonemptyObjectValue(utls, "fingerprint") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.utls.enabled", "uTLS children are set while uTLS is disabled")
		}
	}
	if reality, exists, objectErr := importObject("sing-box.outbound.tls.reality", tls["reality"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"sing-box.outbound.tls.reality", reality,
			queryFieldSet("enabled", "public_key", "short_id"),
		)...)
		if anyBool(reality["enabled"]) {
			switch proxy["type"] {
			case "vmess", "vless", "trojan":
			default:
				return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.reality", "proxy type has no Reality transport")
			}
			publicKey := anyString(reality["public_key"])
			if publicKey == "" {
				return notHonoured, fmt.Errorf("Reality is missing public_key")
			}
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   anyString(reality["short_id"]),
			}
		} else if hasNonemptyObjectValue(reality, "public_key", "short_id") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.reality.enabled", "Reality children are set while Reality is disabled")
		}
	}
	return notHonoured, nil
}

func applySingBoxTransport(proxy map[string]any, raw any) ([]string, error) {
	transport, present, err := importObject("sing-box.outbound.transport", raw)
	if err != nil || !present {
		return nil, err
	}
	network := strings.ToLower(anyString(transport["type"]))
	if network == "" || network == "tcp" {
		return unmappedObjectKeys("sing-box.outbound.transport", transport, queryFieldSet("type")), nil
	}
	proxy["network"] = network
	var notHonoured []string
	switch network {
	case "ws":
		notHonoured = unmappedObjectKeys(
			"sing-box.outbound.transport.ws", transport,
			queryFieldSet("type", "path", "headers", "max_early_data", "early_data_header_name"),
		)
		headers := map[string]string{}
		if rawHeaders, exists, objectErr := importObject("sing-box.outbound.transport.ws.headers", transport["headers"]); objectErr != nil {
			return notHonoured, objectErr
		} else if exists {
			for key, value := range rawHeaders {
				headers[key] = anyString(value)
			}
		}
		wsOpts := map[string]any{"path": anyString(transport["path"]), "headers": headers}
		if earlyData, ok := anyInt(transport["max_early_data"]); ok && earlyData > 0 {
			wsOpts["max-early-data"] = earlyData
		}
		if header := anyString(transport["early_data_header_name"]); header != "" {
			wsOpts["early-data-header-name"] = header
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		notHonoured = unmappedObjectKeys("sing-box.outbound.transport.grpc", transport, queryFieldSet("type", "service_name", "serviceName"))
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": firstAnyString(transport, "service_name", "serviceName")}
	case "http":
		notHonoured = unmappedObjectKeys("sing-box.outbound.transport.http", transport, queryFieldSet("type", "host", "path"))
		proxy["network"] = "h2"
		proxy["h2-opts"] = map[string]any{"host": anyStringSlice(transport["host"]), "path": anyString(transport["path"])}
	default:
		// The field path is an identifier the client looks up, not a sentence --
		// but this one names another product inside it, and the path is what the
		// error prints. Renamed to the dialect rather than the product: the
		// client's table keys off this string, so it stays stable and stays
		// legible without carrying a competitor's name to a screen.
		return nil, unsupportedProxyImportField("json.outbound.transport.type", fmt.Sprintf("unsupported transport %q", network))
	}
	return notHonoured, nil
}

// v2rayOutboundMapping reads one v2ray outbound; the third result is what
// singBoxOutboundMapping's is.
func v2rayOutboundMapping(outbound map[string]any) (map[string]any, bool, []string, error) {
	protocol := strings.ToLower(anyString(outbound["protocol"]))
	switch protocol {
	case "freedom", "blackhole", "dns":
		return nil, true, nil, nil
	}
	notHonoured := unmappedObjectKeys(
		"v2ray.outbound", outbound,
		queryFieldSet("tag", "protocol", "settings", "streamSettings"),
	)
	settings, ok := outbound["settings"].(map[string]any)
	if !ok {
		return nil, false, notHonoured, fmt.Errorf("%s outbound has no settings object", protocol)
	}
	name := anyString(outbound["tag"])
	if name == "" {
		name = protocol
	}
	var proxy map[string]any
	switch protocol {
	case "vmess", "vless":
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings", settings, queryFieldSet("vnext"))...)
		if count := objectArrayLength(settings["vnext"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.vnext", "exactly one endpoint is representable")
		}
		vnext, ok := firstObject(settings["vnext"])
		if !ok {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has no vnext endpoint", protocol)
		}
		port, portOK := anyInt(vnext["port"])
		user, userOK := firstObject(vnext["users"])
		if anyString(vnext["address"]) == "" || !portOK || !userOK {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has an incomplete vnext endpoint", protocol)
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.vnext[0]", vnext, queryFieldSet("address", "port", "users"))...)
		if count := objectArrayLength(vnext["users"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.vnext[0].users", "exactly one user is representable")
		}
		userFields := queryFieldSet("id", "flow", "encryption")
		if protocol == "vmess" {
			mergeFieldSet(userFields, "alterId", "security", "cipher")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.vnext[0].users[0]", user, userFields)...)
		proxy = map[string]any{
			"name": name, "type": protocol, "server": anyString(vnext["address"]), "port": port,
			"uuid": anyString(user["id"]), "udp": true,
		}
		if protocol == "vmess" {
			proxy["alterId"], _ = anyInt(user["alterId"])
			proxy["cipher"] = firstAnyString(user, "security", "cipher")
			if proxy["cipher"] == "" {
				proxy["cipher"] = "auto"
			}
		} else if flow := anyString(user["flow"]); flow != "" {
			proxy["flow"] = flow
		}
	case "trojan", "shadowsocks":
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings", settings, queryFieldSet("servers"))...)
		if count := objectArrayLength(settings["servers"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.servers", "exactly one endpoint is representable")
		}
		server, ok := firstObject(settings["servers"])
		if !ok {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has no server", protocol)
		}
		port, portOK := anyInt(server["port"])
		if anyString(server["address"]) == "" || !portOK {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has an incomplete server", protocol)
		}
		serverFields := queryFieldSet("address", "port", "password")
		if protocol == "shadowsocks" {
			mergeFieldSet(serverFields, "method")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.servers[0]", server, serverFields)...)
		proxy = map[string]any{
			"name": name, "type": protocol, "server": anyString(server["address"]), "port": port, "udp": true,
			"password": anyString(server["password"]),
		}
		if protocol == "shadowsocks" {
			proxy["type"] = "ss"
			proxy["cipher"] = anyString(server["method"])
		}
	default:
		return nil, false, notHonoured, fmt.Errorf("unsupported V2Ray outbound protocol %q", protocol)
	}
	streamNotHonoured, err := applyV2RayStreamSettings(proxy, outbound["streamSettings"])
	notHonoured = append(notHonoured, streamNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	return proxy, false, notHonoured, nil
}

func objectArrayLength(raw any) int {
	items, ok := raw.([]any)
	if !ok {
		return 0
	}
	return len(items)
}

func firstObject(raw any) (map[string]any, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, false
	}
	object, ok := items[0].(map[string]any)
	return object, ok
}

func applyV2RayStreamSettings(proxy map[string]any, raw any) ([]string, error) {
	settings, present, err := importObject("v2ray.outbound.streamSettings", raw)
	if err != nil || !present {
		return nil, err
	}
	notHonoured := unmappedObjectKeys(
		"v2ray.outbound.streamSettings", settings,
		queryFieldSet("network", "security", "tlsSettings", "realitySettings", "wsSettings", "grpcSettings", "httpSettings"),
	)
	network := strings.ToLower(anyString(settings["network"]))
	if network != "" && network != "tcp" {
		proxy["network"] = network
	}
	security := strings.ToLower(anyString(settings["security"]))
	if security == "tls" || security == "reality" {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.security", "proxy type has no representable TLS transport")
		}
	}
	if tlsSettings, exists, objectErr := importObject("v2ray.outbound.streamSettings.tlsSettings", settings["tlsSettings"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.tlsSettings", "proxy type has no representable TLS transport")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.tlsSettings", tlsSettings,
			queryFieldSet("serverName", "allowInsecure", "alpn", "fingerprint"),
		)...)
		if serverName := anyString(tlsSettings["serverName"]); serverName != "" {
			proxy["servername"] = serverName
		}
		if anyBool(tlsSettings["allowInsecure"]) {
			proxy["skip-cert-verify"] = true
		}
		if alpn := anyStringSlice(tlsSettings["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fingerprint := anyString(tlsSettings["fingerprint"]); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
	}
	if realitySettings, exists, objectErr := importObject("v2ray.outbound.streamSettings.realitySettings", settings["realitySettings"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.realitySettings", "proxy type has no Reality transport")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.realitySettings", realitySettings,
			queryFieldSet("serverName", "fingerprint", "publicKey", "shortId"),
		)...)
		publicKey := anyString(realitySettings["publicKey"])
		if publicKey == "" {
			return notHonoured, fmt.Errorf("V2Ray Reality is missing publicKey")
		}
		if serverName := anyString(realitySettings["serverName"]); serverName != "" {
			if proxy["type"] == "vmess" || proxy["type"] == "vless" {
				proxy["servername"] = serverName
			} else {
				proxy["sni"] = serverName
			}
		}
		if fingerprint := anyString(realitySettings["fingerprint"]); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   anyString(realitySettings["shortId"]),
		}
	}
	switch network {
	case "ws":
		ws, _, objectErr := importObject("v2ray.outbound.streamSettings.wsSettings", settings["wsSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.wsSettings", ws,
			queryFieldSet("path", "headers", "maxEarlyData", "earlyDataHeaderName"),
		)...)
		headers := map[string]string{}
		if rawHeaders, exists, headersErr := importObject("v2ray.outbound.streamSettings.wsSettings.headers", ws["headers"]); headersErr != nil {
			return notHonoured, headersErr
		} else if exists {
			for key, value := range rawHeaders {
				headers[key] = anyString(value)
			}
		}
		wsOpts := map[string]any{"path": anyString(ws["path"]), "headers": headers}
		if earlyData, ok := anyInt(ws["maxEarlyData"]); ok && earlyData > 0 {
			wsOpts["max-early-data"] = earlyData
		}
		if header := anyString(ws["earlyDataHeaderName"]); header != "" {
			wsOpts["early-data-header-name"] = header
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		grpc, _, objectErr := importObject("v2ray.outbound.streamSettings.grpcSettings", settings["grpcSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.streamSettings.grpcSettings", grpc, queryFieldSet("serviceName"))...)
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": anyString(grpc["serviceName"])}
	case "h2", "http":
		httpSettings, _, objectErr := importObject("v2ray.outbound.streamSettings.httpSettings", settings["httpSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.streamSettings.httpSettings", httpSettings, queryFieldSet("host", "path"))...)
		proxy["network"] = "h2"
		proxy["h2-opts"] = map[string]any{
			"host": anyStringSlice(httpSettings["host"]), "path": anyString(httpSettings["path"]),
		}
	case "", "tcp":
	default:
		return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.network", fmt.Sprintf("unsupported transport %q", network))
	}
	return notHonoured, nil
}

func anyBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(typed) {
		case "1", "true", "yes", "on":
			return true
		}
	case json.Number:
		return typed.String() == "1"
	}
	return false
}

func anyStringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if text := anyString(value); text != "" {
			return []string{text}
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := anyString(item); text != "" {
			result = append(result, text)
		}
	}
	return result
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// proxyImportDialectOnlyJSONKeys names the spellings jsonServerMapping translates
// away from. An object carrying any of them is a dialect document whatever its
// `type` says, and handing it to the kernel verbatim would drop the very fields
// the mapping exists to carry.
var proxyImportDialectOnlyJSONKeys = queryFieldSet(
	"host", "server_port", "protocol", "remarks", "remark", "title", "id", "group", "ratio",
	"encryption", "method", "alter_id", "security", "peer", "serverName", "tlsServerName",
	"allowInsecure", "allow_insecure", "insecure", "fp", "hpkp", "pbk", "publicKey", "sid",
	"shortId", "fastopen",
)

// jsonObjectIsCanonicalMihomoProxy reports whether a bare JSON object is already
// written in mihomo's own proxy vocabulary. Such an object reaches the kernel
// verbatim -- the same treatment it would get inside `{"proxies": [...]}` --
// because a field ledger in front of the engine we feed makes this importer
// narrower than the engine itself. Which container the caller happened
// to wrap the proxy in is not a fact about the proxy.
func jsonObjectIsCanonicalMihomoProxy(object map[string]any) bool {
	// The type is not checked against this build's capability registry. That
	// registry owns share-link schemes, and the kernel's outbound set is wider
	// than it -- shadowquic, gost-relay, sudoku, openvpn, tailscale and zerotier
	// are proxies mihomo builds and no share link spells. Consulting it here put
	// our narrower table in front of the engine again, which is the defect
	// exists to prevent, only with a different table: the same six types imported
	// from `{"proxies": [...]}` and came back as an unknown format from a bare
	// array. Whether a type is a proxy is the kernel's answer to give.
	if strings.TrimSpace(anyString(object["type"])) == "" {
		return false
	}
	if anyString(object["server"]) == "" || object["port"] == nil {
		return false
	}
	for key := range object {
		if _, dialect := proxyImportDialectOnlyJSONKeys[key]; dialect {
			return false
		}
	}
	return true
}

// canonicalJSONProxyArray returns the proxies and the entries it skipped. An
// entry that is not an object is one record, not the array's verdict: the
// outbound parser learned that on 2026-08-28 and this one had not.
func canonicalJSONProxyArray(items []any) ([]map[string]any, []proxyImportIssue) {
	proxies := make([]map[string]any, 0, len(items))
	var skipped []proxyImportIssue
	for index, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("proxy %d must be an object", index),
			})
			continue
		}
		proxies = append(proxies, normalizeJSONNumbers(proxy))
	}
	return proxies, skipped
}

// parseJSONServerArray returns the nodes, the fields each server named that
// this build did not map parallel to them (notHonoured[i] belongs to
// proxies[i]; they stay parallel rather than being filed here because a notice
// is filed under the name the node ends up with, and that is decided later),
// and the servers it could not read. A server with no port is one record, not
// the document's verdict; the keys it named ride with its skip because there
// is no node to file them under.
func parseJSONServerArray(items []any, defaults map[string]any) ([]map[string]any, [][]string, []proxyImportIssue) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	var skipped []proxyImportIssue
	for index, item := range items {
		server, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("server %d must be an object", index),
			})
			continue
		}
		proxy, notices, err := jsonServerMapping(server, defaults)
		if err != nil {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Scheme: strings.ToLower(firstAnyString(server, "type", "protocol")),
				Code: "malformedRecord", Message: fmt.Sprintf("server %d: %v", index, err),
				AlsoNotHonoured: proxyImportNoticeMessages(notices),
			})
			continue
		}
		proxies = append(proxies, proxy)
		notHonoured = append(notHonoured, notices)
	}
	return proxies, notHonoured, skipped
}

func jsonServerMapping(server, defaults map[string]any) (map[string]any, []string, error) {
	value := func(keys ...string) any {
		for _, key := range keys {
			if item := server[key]; item != nil {
				return item
			}
		}
		for _, key := range keys {
			if defaults != nil {
				if item := defaults[key]; item != nil {
					return item
				}
			}
		}
		return nil
	}
	kind := strings.ToLower(firstAnyString(server, "type", "protocol"))
	if kind == "" && defaults != nil {
		candidate := strings.ToLower(firstAnyString(defaults, "type", "protocol"))
		// `type: Shadowrocket` names the container, not every server in it.
		if candidate != "shadowrocket" {
			kind = candidate
		}
	}
	if kind == "" && value("method", "encryption") != nil {
		kind = "ss"
	}
	allowed := queryFieldSet(
		"server", "host", "server_port", "port", "type", "protocol", "remarks", "remark", "title", "name",
		"id", "group", "ratio",
	)
	switch kind {
	case "ss", "shadowsocks":
		mergeFieldSet(allowed, "method", "encryption", "cipher", "password", "plugin")
	case "trojan", "hysteria2", "hy2", "anytls":
		mergeFieldSet(allowed, "password")
	case "vless", "vmess":
		mergeFieldSet(allowed, "uuid", "password", "flow", "alterId", "alter_id", "security", "cipher")
	}
	switch kind {
	case "trojan", "hysteria2", "hy2", "anytls", "vless", "vmess":
		mergeFieldSet(
			allowed, "tls", "security", "sni", "peer", "serverName", "tlsServerName", "allowInsecure",
			"allow_insecure", "insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp",
			"pbk", "publicKey", "sid", "shortId", "tfo", "fastopen", "udp",
		)
	}
	notHonoured := unmappedObjectKeys("json.server", server, allowed)
	host := anyString(value("server", "host"))
	port, ok := anyInt(value("server_port", "port"))
	if host == "" || !ok || port < 1 || port > 65535 {
		return nil, notHonoured, fmt.Errorf("missing server or port")
	}
	name := anyString(value("remarks", "remark", "title", "name"))
	if name == "" {
		name = host
	}
	proxy := map[string]any{"name": name, "server": host, "port": port, "udp": true}
	switch kind {
	case "ss", "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = anyString(value("method", "encryption", "cipher"))
		proxy["password"] = anyString(value("password"))
		if plugin := anyString(value("plugin")); plugin != "" {
			proxy["plugin"] = plugin
		}
	case "trojan", "hysteria2", "hy2", "anytls":
		if kind == "hy2" {
			kind = "hysteria2"
		}
		proxy["type"] = kind
		proxy["password"] = anyString(value("password"))
	case "vless", "vmess":
		proxy["type"] = kind
		proxy["uuid"] = anyString(value("uuid", "password"))
		if kind == "vmess" {
			proxy["alterId"], _ = anyInt(value("alterId", "alter_id"))
			proxy["cipher"] = firstAnyString(server, "security", "cipher")
			if proxy["cipher"] == "" {
				proxy["cipher"] = "auto"
			}
		} else if flow := anyString(value("flow")); flow != "" {
			proxy["flow"] = flow
		}
	default:
		return nil, notHonoured, fmt.Errorf("unsupported JSON server type %q", kind)
	}
	if sni := anyString(value("sni", "peer", "serverName", "tlsServerName")); sni != "" {
		if kind == "vless" || kind == "vmess" {
			proxy["servername"] = sni
		} else {
			proxy["sni"] = sni
		}
	}
	security := strings.ToLower(anyString(value("security")))
	publicKey := anyString(value("pbk", "publicKey"))
	if anyBool(value("tls")) || security == "tls" || security == "reality" || publicKey != "" {
		proxy["tls"] = true
	}
	if anyBool(value("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify")) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := splitListValues(anyStringSlice(value("alpn"))); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := anyString(value("fp", "fingerprint")); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), anyString(value("hpkp"))); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey != "" {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   anyString(value("sid", "shortId")),
			}
		default:
			return nil, notHonoured, unsupportedProxyImportField("json.server.reality", "proxy type has no Reality transport")
		}
	}
	if anyBool(value("tfo", "fastopen")) {
		proxy["tfo"] = true
	}
	if udp := value("udp"); udp != nil {
		proxy["udp"] = anyBool(udp)
	}
	return proxy, notHonoured, nil
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	default:
		return ""
	}
}

func anyInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	case float64:
		return int(typed), typed == float64(int(typed))
	case string:
		parsed, err := strconv.Atoi(typed)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func normalizeJSONNumbers(mapping map[string]any) map[string]any {
	for key, value := range mapping {
		switch typed := value.(type) {
		case json.Number:
			if integer, err := strconv.Atoi(typed.String()); err == nil {
				mapping[key] = integer
			} else if number, err := typed.Float64(); err == nil {
				mapping[key] = number
			}
		case map[string]any:
			mapping[key] = normalizeJSONNumbers(typed)
		case []any:
			for index, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					typed[index] = normalizeJSONNumbers(nested)
				}
			}
		}
	}
	return mapping
}

func parseSSDSubscription(text string) ([]map[string]any, [][]string, []proxyImportIssue, error) {
	body := strings.TrimSpace(text[len("ssd://"):])
	decoded, err := convert.TryDecodeBase64(body)
	if err != nil {
		return nil, nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, nil, err
	}
	servers, ok := document["servers"].([]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("SSD servers must be an array")
	}
	proxies, notHonoured, skipped := parseJSONServerArray(servers, document)
	return proxies, notHonoured, skipped, nil
}

func parseWireGuardINI(text string) (map[string]any, error) {
	sections := map[string]map[string][]string{}
	sectionCounts := map[string]int{}
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			sectionCounts[section]++
			if sections[section] == nil {
				sections[section] = make(map[string][]string)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return nil, fmt.Errorf("invalid WireGuard INI line %q", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		sections[section][key] = append(sections[section][key], strings.TrimSpace(value))
	}
	for name := range sections {
		if name != "interface" && name != "peer" {
			return nil, unsupportedProxyImportField("wireguard.ini."+name, "only Interface and Peer sections are representable")
		}
	}
	iface, peer := sections["interface"], sections["peer"]
	if iface == nil || peer == nil {
		return nil, fmt.Errorf("WireGuard INI requires Interface and Peer sections")
	}
	if sectionCounts["interface"] != 1 || sectionCounts["peer"] != 1 {
		return nil, fmt.Errorf("WireGuard INI requires exactly one Interface and exactly one Peer")
	}
	if err := validateINISectionKeys(
		"wireguard.ini.interface", iface,
		queryFieldSet("privatekey", "address", "dns", "mtu", "listenport"),
	); err != nil {
		return nil, err
	}
	if err := validateINISectionKeys(
		"wireguard.ini.peer", peer,
		// AllowedIPs belongs to the source routing policy. A proxy outbound
		// receives routing from mihomo, so it is explicitly metadata-only here.
		queryFieldSet("publickey", "presharedkey", "endpoint", "persistentkeepalive", "allowedips"),
	); err != nil {
		return nil, err
	}
	endpoint := firstINIValue(peer, "endpoint")
	server, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard endpoint: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid WireGuard endpoint port")
	}
	addresses := splitListValues(iface["address"])
	ipv4, ipv6 := splitIPValues(addresses)
	privateKey := firstINIValue(iface, "privatekey")
	publicKey := firstINIValue(peer, "publickey")
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("WireGuard INI requires PrivateKey, Address and PublicKey")
	}
	proxy := map[string]any{
		"name": endpoint, "type": "wireguard", "server": server, "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if psk := firstINIValue(peer, "presharedkey"); psk != "" {
		proxy["pre-shared-key"] = psk
	}
	if dns := splitListValues(iface["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if mtuText := firstINIValue(iface, "mtu"); mtuText != "" {
		mtu, parseErr := strconv.Atoi(mtuText)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid WireGuard MTU %q", mtuText)
		}
		proxy["mtu"] = mtu
	}
	if keepaliveText := firstINIValue(peer, "persistentkeepalive"); keepaliveText != "" {
		keepalive, parseErr := strconv.Atoi(keepaliveText)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid WireGuard keepalive %q", keepaliveText)
		}
		proxy["persistent-keepalive"] = keepalive
	}
	return proxy, nil
}

func validateINISectionKeys(prefix string, values map[string][]string, allowed map[string]struct{}) error {
	for key := range values {
		if _, ok := allowed[key]; ok {
			continue
		}
		return unsupportedProxyImportField(prefix+"."+key, "INI field is not mapped by this importer build")
	}
	return nil
}

func firstINIValue(section map[string][]string, key string) string {
	values := section[key]
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

type proxyImportRecord struct {
	scheme string
	text   string
	// line counts from one and offset from zero, both into the text the reader
	// pasted. A reader cannot count records; they can find line 3.
	line   int
	offset int
}

func extractProxyImportRecords(text string) []proxyImportRecord {
	matches := proxyImportURLPattern.FindAllStringSubmatchIndex(text, -1)
	records := make([]proxyImportRecord, 0, len(matches))
	for index, match := range matches {
		end := len(text)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		// Human-facing share sheets commonly wrap a URI in prose. A URI record
		// never crosses a line boundary; without this bound the next explanatory
		// line becomes part of the preceding fragment. The next scheme remains a
		// second bound so multiple records separated by a pipe still work.
		if lineEnd := strings.IndexAny(text[match[0]:end], "\r\n"); lineEnd >= 0 {
			end = match[0] + lineEnd
		}
		record := trimProxyImportRecordEdges(text, match[0], end)
		if record == "" {
			continue
		}
		records = append(records, proxyImportRecord{
			scheme: text[match[2]:match[3]],
			text:   record,
			line:   strings.Count(text[:match[0]], "\n") + 1,
			offset: match[0],
		})
	}
	return records
}

// proxyImportRecordClosers pairs each closing mark this trims with the opener
// that has to be there for it to be prose rather than part of the link.
var proxyImportRecordClosers = map[rune]rune{
	')': '(', ']': '[', '}': '{', '>': '<', '"': '"', '\'': '\'', '`': '`',
	'）': '（', '］': '［', '｝': '｛', '》': '《', '」': '「', '』': '『', '】': '【', '”': '“', '’': '‘',
}

// proxyImportRecordEdgeTrim is what comes off a record's end regardless of what
// precedes it: whitespace and the punctuation prose puts after a link.
const proxyImportRecordEdgeTrim = " \t\r\n|,;.，。、"

// trimProxyImportRecordEdges peels prose off a share link without eating the
// link's own name.
//
// A person's clipboard often carries the URI inside a sentence -- "(use
// ss://… )" -- so trailing brackets and punctuation come off. The plain trim
// this replaced took `)` unconditionally, and an airport that ends a node's
// `…(hy2`. Shadowrocket writes those brackets unencoded and `(hy2)`, `(IEPL)`,
// `(BGP)` are ordinary airport naming, so this was quietly renaming nodes --
// and renaming without saying so is the thing the client lanes ruled against,
// except here nobody knew it was happening.
//
// A closing bracket is prose only if an opening one is waiting for it. The
// check looks at what came before the link on the same line, which is where the
// opener would be, and keeps the bracket otherwise.
//
// Found by the macOS lane on a real airport link. Its first sweep missed it
// because the fixtures were built with url.QueryEscape, so every bracket in
// them was percent-encoded -- and a percent-encoded one was never at risk.
func trimProxyImportRecordEdges(text string, start, end int) string {
	before := text[:start]
	if lineStart := strings.LastIndexAny(before, "\r\n"); lineStart >= 0 {
		before = before[lineStart+1:]
	}
	record := strings.TrimRight(strings.TrimLeft(text[start:end], proxyImportRecordEdgeTrim), proxyImportRecordEdgeTrim)
	for {
		trimmed := strings.TrimRight(record, proxyImportRecordEdgeTrim)
		if trimmed == "" {
			return ""
		}
		last := []rune(trimmed)[len([]rune(trimmed))-1]
		opener, closing := proxyImportRecordClosers[last]
		if !closing || !strings.ContainsRune(before, opener) {
			return trimmed
		}
		record = string([]rune(trimmed)[:len([]rune(trimmed))-1])
	}
}

func normalizeProxyImportAlias(link, scheme, canonicalType string) string {
	// CanonicalType is the outbound type, not necessarily the URI spelling.
	// https and mierus carry semantics/spellings understood by the upstream
	// converter and therefore must not be rewritten to http/mieru.
	if scheme == canonicalType || canonicalType == "" || scheme == "https" || scheme == "mierus" ||
		strings.HasSuffix(scheme, "+realm") {
		return link
	}
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link
	}
	return canonicalType + link[separator:]
}

// makeProxyImportNameUnique gives every imported node a name that is its own.
//
// It used to return early on an empty name, and five of the ten schemes reach
// here with one: ss, trojan, vless, tuic and hysteria2 build their map in this
// file, while anytls, socks5, http, snell and ssh come back from upstream's
// converter already carrying host:port. Two unnamed links of the first kind
// produced a configuration the kernel then refused outright --
// `proxy  is the duplicate name` (config.go:960) -- so a person who pasted two
// links without a #fragment got a profile that would not load, and nothing in
// the import said why.
//
// The fallback is the same host:port the other five already use, so the five
// that were empty now look like the five that were not. That also makes the
// name usable as identity: the import report names which node a dropped field
// belonged to, and an empty name would have pointed every notice at whichever
// blank-named node came first.
//
// Found by the iOS lane sampling four schemes and the macOS lane sampling five.
// This tree's own check had sampled one -- anytls, the scheme where it worked.
// proxyImportIdentity answers "are these two links the same node" for the
// client, which is where duplicate collapsing belongs: this function sees only
// what was pasted just now, while the duplicate a person actually meets is the
// one already in their profile from last week.
//
// The identity is every field the node carries, name included, over the map as
// it stands before renaming. Both halves of that matter and they pull in
// opposite directions:
//
//   - Including the name keeps two links that differ only in what the airport
//     called them apart. Same server, same port, same password, one labelled
//     "HK" and one "TW" is two exits behind one front door, and collapsing them
//     would take away a choice the person was given.
//   - Using the name from the link rather than the final one is what lets exact
//     duplicates collapse at all. makeProxyImportNameUnique turns the second
//     "HK" into "HK-01", so an identity computed afterwards would find no two
//     nodes alike and collapse nothing.
//
// So this is computed before the rename, and the notices are stamped after it.
// Nothing here decides what happens to a duplicate; it hands the client the one
// piece of the judgement that needs to know what a field means to an outbound.
func proxyImportIdentity(proxy map[string]any) string {
	canonical, err := json.Marshal(canonicalProxyImportValue(proxy))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalProxyImportValue rewrites a decoded proxy into a form whose JSON
// encoding is stable. Go's encoder already sorts map keys, but a value that
// arrived as a YAML map is map[any]any, which it refuses outright.
func canonicalProxyImportValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[key] = canonicalProxyImportValue(inner)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[fmt.Sprint(key)] = canonicalProxyImportValue(inner)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, inner := range typed {
			out[index] = canonicalProxyImportValue(inner)
		}
		return out
	default:
		return value
	}
}

func makeProxyImportNameUnique(proxy map[string]any, seen map[string]int) {
	name, _ := proxy["name"].(string)
	if name == "" {
		server, _ := proxy["server"].(string)
		if server == "" {
			return
		}
		name = server
		if port := proxy["port"]; port != nil {
			name = fmt.Sprintf("%s:%v", server, port)
		}
		proxy["name"] = name
	}
	count := seen[name]
	seen[name] = count + 1
	if count > 0 {
		proxy["name"] = fmt.Sprintf("%s-%02d", name, count)
	}
}

// convertProxyShareLinks is the Hako-owned compatibility boundary in front of
// mihomo's share-link converter. Ecosystem clients have emitted URI dialects
// that the upstream converter does not reconstruct correctly; normalize those
// dialects here instead of carrying an Apple-client parser or patching upstream.
func convertProxyShareLinks(payload []byte, tolerateUnmappedFields bool) ([]map[string]any, error) {
	text := string(normalizeLegacyVlessPayload(payload))
	if !proxyImportURLPattern.MatchString(text) {
		return nil, fmt.Errorf("hako: proxy payload format is invalid")
	}
	capabilities := proxyImportCapabilityMap()
	records := extractProxyImportRecords(text)
	proxies := make([]map[string]any, 0, len(records))
	seenNames := make(map[string]int)
	for _, record := range records {
		capability, ok := capabilities[strings.ToLower(record.scheme)]
		if !ok {
			// Subscription context: upstream's converter skips a line whose
			// scheme it does not know (common/convert/converter.go cuts on
			// "://" and falls through unknown cases), so a subscription that
			// mixes in one new protocol still yields every other node.
			// Refusing the whole payload here is what turned one unknown
			// line into an empty provider.
			if tolerateUnmappedFields {
				continue
			}
			return nil, fmt.Errorf("hako: proxy scheme %q is not recognized", record.scheme)
		}
		if capability.Status != proxyImportSupported {
			if tolerateUnmappedFields {
				continue
			}
			return nil, fmt.Errorf("hako: proxy scheme %q is not supported by the Core importer", record.scheme)
		}
		parsed, _, err := parseProxyShareLinkTolerating(
			record.text, capability, tolerateUnmappedFields,
		)
		if err != nil {
			// A line of a supported scheme that still does not parse is also
			// a skipped line upstream, not a dead subscription.
			if tolerateUnmappedFields {
				continue
			}
			return nil, err
		}
		for _, proxy := range parsed {
			makeProxyImportNameUnique(proxy, seenNames)
			proxies = append(proxies, proxy)
		}
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("hako: proxy payload did not contain a supported proxy")
	}
	return proxies, nil
}

func proxyImportCapabilityMap() map[string]proxyImportCapability {
	capabilities := make(map[string]proxyImportCapability, len(proxyImportCapabilities))
	for _, capability := range proxyImportCapabilities {
		capabilities[capability.Scheme] = capability
	}
	return capabilities
}

// parseProxyShareLink is the inspect path's entry, and it tolerates unmapped
// keys for the same reason ConvertProxiesForIOS does -- which it did not until
// 2026-08-28, so the two doors disagreed about the same link.
//
// This is the door a person actually stands at: the client calls inspect first,
// to show what was pasted before anything is saved. A link carrying one key
// this build's whitelist does not list came back with the node skipped, so the
// report said "nothing imported" while the other entry point, given the same
// bytes, produced the node. The fix to that whitelist landed on the other door
// only, and the gate written to hold it measured only that door.
//
// The whitelist is not the judgement, it is a lookup. Upstream reads the keys
// it knows and ignores the rest; a key nobody registered is a key nobody
// registered, not a broken link.
func parseProxyShareLink(link string, capability proxyImportCapability) ([]map[string]any, []string, error) {
	return parseProxyShareLinkTolerating(link, capability, true)
}

// dropEmptyProxyImportValues removes the keys this importer would otherwise
// write as an empty string.
//
// An absent key and an empty one are the same thing to mihomo's decoder --
// except where the outbound seeds a default before decoding, and then they are
// opposites. `simpleObfsOption{Host: "bing.com"}` (adapter/outbound/snell.go:172
// and shadowsocks.go:322) is the case that showed it: a snell link with
// `obfs=http` and no host came out carrying `obfs-opts.host: ""`, which
// replaced upstream's bing.com with nothing, and an HTTP obfs sending an empty
// Host header is the shape a middlebox drops. Seven of seven probe links wrote
// at least one empty value; ws-opts.path, grpc-opts.grpc-service-name,
// plugin-opts.host and hysteria2's sni were the others.
//
// Omitting is never worse than writing empty: where no default exists the
// decoder produces the same zero value either way, and where one exists the
// person keeps it. So this is a blanket sweep rather than a list of the fields
// that were found, which would go stale the next time a constructor writes one.
//
// The macOS lane found this by printing what the importer produced rather than
// by reading it. In source, `obfs-opts` with a `host` key looks entirely
// correct.
func dropEmptyProxyImportValues(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			// `name` is the exception, and it is one because it is filled in
			// later rather than because an empty one is wanted. A link with no
			// #fragment reaches here nameless and gets host:port from
			// makeProxyImportNameUnique -- but adapter.ParseProxy runs first, and
			// mihomo requires the key to be present: sweeping it away turned five
			// schemes' unnamed links into `'' has unset fields: name`.
			if key == "name" {
				continue
			}
			if text, ok := inner.(string); ok && text == "" {
				delete(typed, key)
				continue
			}
			dropEmptyProxyImportValues(inner)
		}
	case []any:
		for _, inner := range typed {
			dropEmptyProxyImportValues(inner)
		}
	}
}

// certificatePinOrNothing returns the value only when mihomo can use it as a
// certificate pin, and "" otherwise.
//
// `fingerprint` means two different things across this family. On vless and
// vmess an exporter writes a uTLS browser name into it and this importer maps
// it to client-fingerprint; on hysteria, hysteria2, tuic and trojan the field
// mihomo calls `fingerprint` is a certificate pin and wants sha256 hex.
// Exporters paste the same `fingerprint=chrome` onto every scheme, and mapping
// it onto the pin field made adapter.ParseProxy refuse the node -- upstream
// ignored the key entirely and imported a working one.
//
// The check is upstream's own verifier rather than a shape test written here,
// so it cannot drift from what the outbound will accept: it is the function
// that produces the refusal being avoided.
// proxyTypesThatVerifyTheirFingerprint is the set of outbounds that run
// mihomo's pin verifier while the node is being parsed, so a value it cannot
// use costs the node instead of being ignored.
//
// The rest accept anything in the field: trojan, vmess, vless, anytls and ss
// all load with `fingerprint: chrome`. Filtering there would be this tree
// refusing what the kernel accepts, which is the defect this whole family is,
// so the check is scoped to where not filtering loses the node.
//
// The set is measured, not asserted: TestOnlySomeOutboundsVerifyTheirFingerprint
// drives adapter.ParseProxy for every type here and every type not here, so the
// day upstream starts or stops verifying one, the list is wrong out loud.
var proxyTypesThatVerifyTheirFingerprint = map[string]struct{}{
	"hysteria": {}, "hysteria2": {}, "tuic": {},
}

// hysteria2CertificatePin is the alias normaliser's view of the same check.
// The branch it sits in is hysteria2's, and at that point there is no proxy map
// to read a type from -- the query is still being rewritten for upstream's
// converter to read.
func hysteria2CertificatePin(value string) string {
	return certificatePinOrNothing("hysteria2", value)
}

func certificatePinOrNothing(proxyType, value string) string {
	if value == "" {
		return ""
	}
	if _, verifies := proxyTypesThatVerifyTheirFingerprint[proxyType]; !verifies {
		return value
	}
	if _, err := ca.NewFingerprintVerifier(value, time.Now); err != nil {
		return ""
	}
	return value
}

// realityPublicKeyOrNothing returns the value only when mihomo can build a
// REALITY config from it.
//
// Same shape as the pin: `pbk` arrives on schemes whose outbound has no Reality
// transport at all (registered as not honoured), and on the ones that do it can
// still be a key an exporter invented. Writing it anyway cost the node, while
// upstream -- which does not read the key on these schemes -- imported it.
//
// This is the distinction to keep when reading the not-honoured table: a
// missing Reality key is tolerated, a malformed one is not silently accepted.
// It is not that Reality stopped being validated.
func realityPublicKeyOrNothing(value string) string {
	if value == "" {
		return ""
	}
	if _, err := (outbound.RealityOptions{PublicKey: value}).Parse(); err != nil {
		return ""
	}
	return value
}

func parseProxyShareLinkTolerating(
	link string, capability proxyImportCapability, tolerateUnmapped bool,
) ([]map[string]any, []string, error) {
	notHonoured, err := validateProxyShareLinkQueryFields(link, capability, tolerateUnmapped)
	if err != nil {
		return nil, nil, err
	}
	proxies, portRange, bodyNotHonoured, parseErr := parseProxyShareLinkRecord(link, capability)
	for _, proxy := range proxies {
		dropEmptyProxyImportValues(proxy)
	}
	// A key in a vmess base64-JSON body that this build does not map is named
	// the way an unmapped query key is, and it is never a refusal: the query
	// keys answer to tolerateUnmapped because one self-test still asks for the
	// strict reading, but the body keys were released outright on 2026-09-02
	// (see unmappedObjectKeys), and nothing asks for them to refuse.
	notHonoured = append(notHonoured, bodyNotHonoured...)
	if portRange != "" {
		notHonoured = append(notHonoured, capability.Scheme+".authority.ports="+portRange+
			": mihomo's "+capability.CanonicalType+" outbound has no port-hopping option, so only the first port is used")
	}
	return proxies, notHonoured, parseErr
}

// parseProxyShareLinkRecord returns the nodes, the port range a hopping link
// carried, and the keys of a vmess base64-JSON body this build did not map
// (nil for every other spelling).
func parseProxyShareLinkRecord(link string, capability proxyImportCapability) ([]map[string]any, string, []string, error) {
	var (
		vmessJSON       map[string]any
		bodyNotHonoured []string
	)
	if capability.CanonicalType == "vmess" {
		if proxy, dropped, matched, err := parseLegacyVMessShareLink(link); matched {
			proxies, err := singletonProxy(proxy, err)
			return proxies, dropped, nil, err
		}
		var matched bool
		var err error
		vmessJSON, bodyNotHonoured, matched, err = parseVMessJSONShareLinkFields(link)
		if matched && err != nil {
			return nil, "", bodyNotHonoured, err
		}
	}
	switch capability.CanonicalType {
	case "snell":
		proxy, err := parseSnellShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "ssh":
		proxy, err := parseSSHShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "wireguard":
		proxy, err := parseWireGuardShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "masque":
		proxy, err := parseMasqueShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "trusttunnel":
		proxy, err := parseTrustTunnelShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	}

	// From here on every failure returns bodyNotHonoured with it. A vmess body
	// with no `ps` is dropped by upstream's converter and yields no node; the
	// keys it named that nobody maps then ride with the skip, the way a
	// container record's do, instead of vanishing with the record.
	normalized, parsed, portRange, err := normalizeProxyShareLinkDialect(link, capability)
	if err != nil {
		return nil, "", bodyNotHonoured, err
	}
	proxies, err := convert.ConvertsV2Ray([]byte(normalized))
	if err != nil {
		return nil, "", bodyNotHonoured, err
	}
	if len(proxies) == 0 {
		return nil, "", bodyNotHonoured, fmt.Errorf("hako: %s proxy URI was not accepted by the dialect parser", capability.Scheme)
	}
	for _, proxy := range proxies {
		if vmessJSON != nil {
			applyVMessJSONShareLinkFields(proxy, vmessJSON)
		}
		if err := applyProxyShareLinkDialect(proxy, parsed); err != nil {
			return nil, "", bodyNotHonoured, err
		}
	}
	return proxies, portRange, bodyNotHonoured, nil
}

// parseVMessJSONShareLinkFields reads the base64-JSON body of a vmess link.
// The second result names the body keys this build does not map; the third
// says whether the link was that spelling at all.
func parseVMessJSONShareLinkFields(link string) (map[string]any, []string, bool, error) {
	trimmed := strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		return nil, nil, false, nil
	}
	body := trimmed[len("vmess://"):]
	if boundary := strings.IndexAny(body, "?#"); boundary >= 0 {
		body = body[:boundary]
	}
	decoded, err := convert.TryDecodeBase64(body)
	if err != nil || len(bytes.TrimSpace(decoded)) == 0 || bytes.TrimSpace(decoded)[0] != '{' {
		return nil, nil, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return nil, nil, true, fmt.Errorf("hako: malformed VMess base64 JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, nil, true, fmt.Errorf("hako: malformed VMess base64 JSON: %w", err)
	}
	allowed := queryFieldSet(
		"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni",
		"alpn", "allowInsecure", "skip-cert-verify", "fp", "fingerprint", "hpkp", "pbk", "sid", "security",
		"udp", "tfo", "packetEncoding", "encryption",
	)
	return values, unmappedObjectKeys("vmess.base64-json", values, allowed), true, nil
}

func applyVMessJSONShareLinkFields(proxy map[string]any, values map[string]any) {
	if anyBool(values["allowInsecure"]) || anyBool(values["skip-cert-verify"]) {
		proxy["skip-cert-verify"] = true
	}
	if fingerprint := firstAnyString(values, "fp", "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), anyString(values["hpkp"])); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey := realityPublicKeyOrNothing(anyString(values["pbk"])); publicKey != "" {
		proxy["tls"] = true
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   anyString(values["sid"]),
		}
	}
	if strings.EqualFold(anyString(values["security"]), "reality") || strings.EqualFold(anyString(values["tls"]), "reality") {
		proxy["tls"] = true
	}
	if anyBool(values["tfo"]) {
		proxy["tfo"] = true
	}
	if udp, exists := values["udp"]; exists {
		proxy["udp"] = anyBool(udp)
	}
}

// proxyImportUnhonouredFields names, per canonical type, the exporter fields this
// build accepts and then does not act on, and why. Refusing the whole record over
// one of these costs the reader a node that would have worked; honouring it is not
// possible because the kernel has nowhere to put it. So the record imports and the
// field is named in the report instead.
//
// Membership is the registration the ruling requires: a field reaches this table
// only after being looked up in the kernel's option struct and found to have no
// equivalent, with that finding written next to it. Anything not in the table --
// including a field nobody has looked up yet -- still refuses the whole record,
// because the one that bit us (mport) was connection-critical and a blanket
// pass-through would have produced a node that looks complete and cannot connect.
const proxyImportMasqueNoWireGuardFields = "mihomo's masque outbound authenticates with a key pair and has no equivalent for these WireGuard-shaped fields"

const proxyImportSnellNoTLS = "mihomo's snell outbound has no TLS, so there is nothing for this field to configure"

const proxyImportMieruNoTLS = "mihomo's mieru outbound has no TLS, so there is nothing to configure with it"

// The sentence is generated rather than written out per scheme so that the nine
// entries above cannot drift into nine slightly different explanations of the
// same fact.
func proxyImportNoRealityTransport(display string) string {
	return "mihomo's " + display + " outbound has no Reality transport"
}

var proxyImportUnhonouredFields = map[string]map[string]string{
	"socks5": {
		// adapter/outbound/socks5.go: Socks5Option carries tls, skip-cert-verify,
		// fingerprint and certificate, and no server-name or alpn field.
		"alpn":          "mihomo's socks5 outbound has no alpn field",
		"peer":          "mihomo's socks5 outbound has no server-name field",
		"sni":           "mihomo's socks5 outbound has no server-name field",
		"serverName":    "mihomo's socks5 outbound has no server-name field",
		"tlsServerName": "mihomo's socks5 outbound has no server-name field",
	},
	"trojan": {
		"mux": proxyImportMuxNotHonoured,
	},
	"vmess": {
		"mux": proxyImportMuxNotHonoured,
	},
	"vless": {
		"mux": proxyImportMuxNotHonoured,
	},
	"snell": {
		// adapter/outbound/snell.go: SnellOption carries psk, version, reuse and
		// obfs-opts -- no TLS. The exporter writes these when TLS parameters were
		// fed to a snell node; they mean nothing here.
		"security": "mihomo's snell outbound has no TLS or security field",
		"alpn":     "mihomo's snell outbound has no TLS, so there is no ALPN to set",
		// The same fact, reached from the other direction: these arrive on snell
		// links from exporters that write a TLS block onto every scheme.
		"keepalive":   "mihomo's snell outbound has no keepalive field",
		"fingerprint": proxyImportSnellNoTLS,
		"hpkp":        proxyImportSnellNoTLS,
		"publicKey":   proxyImportSnellNoTLS,
		"sid":         proxyImportSnellNoTLS,
		"shortId":     proxyImportSnellNoTLS,
	},
	// The nine families below were refusing the whole node from inside their
	// constructors, and the fix is where they are written, not how loudly.
	//
	// Ask the macOS lane's question of each: drop this field, and is the rest
	// still the same usable node? A keepalive is a local timer that never
	// reaches the wire. A `sni` on WireGuard names a TLS layer WireGuard does
	// not have. Reality keys on a protocol whose outbound has no Reality
	// transport cannot be acted on either way. In every one of them the answer
	// is yes, and refusing cost the user a node that would have worked.
	//
	// Reality deserves the argument spelled out, because refusing looks
	// defensible: if the server really is Reality, a node built without it will
	// not connect. But nothing in the link distinguishes "this server is
	// Reality" from "the airport's template leaked a key it pastes into every
	// scheme", and the user's own subscription tonight carried exactly that
	// kind of leaked key. Upstream ignores these and connects. So refusing wins
	// nothing when the key is real (both sides fail to connect) and loses a
	// working node when it is not. It can only lose.
	//
	// What stays a refusal is a different shape entirely: a document that
	// describes several distinct servers when only one is representable. That
	// is not a dropped field, it is picking a server the user did not pick.
	"anytls": {
		"keepalive": "mihomo's anytls outbound has no keepalive field",
		"pbk":       proxyImportNoRealityTransport("AnyTLS"),
		"publicKey": proxyImportNoRealityTransport("AnyTLS"),
		"sid":       proxyImportNoRealityTransport("AnyTLS"),
		"shortId":   proxyImportNoRealityTransport("AnyTLS"),
	},
	"hysteria": {
		"keepalive": "mihomo's hysteria outbound has no keepalive field",
	},
	"hysteria2": {
		"keepalive": "mihomo's hysteria2 outbound has no keepalive field",
		"pbk":       proxyImportNoRealityTransport("Hysteria2"),
		"publicKey": proxyImportNoRealityTransport("Hysteria2"),
		"sid":       proxyImportNoRealityTransport("Hysteria2"),
		"shortId":   proxyImportNoRealityTransport("Hysteria2"),
	},
	"tuic": {
		"pbk":       proxyImportNoRealityTransport("TUIC"),
		"publicKey": proxyImportNoRealityTransport("TUIC"),
		"sid":       proxyImportNoRealityTransport("TUIC"),
		"shortId":   proxyImportNoRealityTransport("TUIC"),
	},
	"http": {
		"pbk":       proxyImportNoRealityTransport("HTTP proxy"),
		"publicKey": proxyImportNoRealityTransport("HTTP proxy"),
		"sid":       proxyImportNoRealityTransport("HTTP proxy"),
		"shortId":   proxyImportNoRealityTransport("HTTP proxy"),
	},
	// adapter/outbound/mieru.go: MieruOption has transport, multiplexing and
	// handshake-mode, and no TLS of any kind. Every TLS-shaped key an airport
	// pastes onto a mieru link names a layer that is not there.
	"mieru": {
		"peer":             proxyImportMieruNoTLS,
		"sni":              proxyImportMieruNoTLS,
		"alpn":             proxyImportMieruNoTLS,
		"hpkp":             proxyImportMieruNoTLS,
		"fingerprint":      proxyImportMieruNoTLS,
		"insecure":         proxyImportMieruNoTLS,
		"allowInsecure":    proxyImportMieruNoTLS,
		"allow_insecure":   proxyImportMieruNoTLS,
		"skip-cert-verify": proxyImportMieruNoTLS,
		"pbk":              proxyImportMieruNoTLS,
		"publicKey":        proxyImportMieruNoTLS,
		"sid":              proxyImportMieruNoTLS,
		"shortId":          proxyImportMieruNoTLS,
	},
	"wireguard": {
		"sni":  "mihomo's wireguard outbound has no TLS, so there is no server name to set",
		"peer": "mihomo's wireguard outbound has no TLS, so there is no server name to set",
	},
	// adapter/outbound/masque.go: MasqueOption authenticates with a key pair and
	// has no pre-shared key, no password and no reserved bytes. Every one of
	// these is WireGuard-shaped, and an exporter that fed a WireGuard node into
	// a masque link left them behind.
	"masque": {
		"presharedKey":   proxyImportMasqueNoWireGuardFields,
		"preSharedKey":   proxyImportMasqueNoWireGuardFields,
		"pre-shared-key": proxyImportMasqueNoWireGuardFields,
		"password":       proxyImportMasqueNoWireGuardFields,
		"keepalive":      proxyImportMasqueNoWireGuardFields,
		"reserved":       proxyImportMasqueNoWireGuardFields,
	},
	// adapter/outbound/ssh.go: SSHOption has no keepalive, and no path -- the
	// key travels in private-key, not as a filename this process could read.
	"ssh": {
		"keepalive": "mihomo's ssh outbound has no keepalive field",
		"path":      "mihomo's ssh outbound takes the key itself in private-key, not a path to read it from",
	},
	"ss": {
		// adapter/outbound/shadowsocks.go: ShadowSocksOption carries no TLS of any
		// kind. The exporter writes security=1 when a reality/TLS input was fed to
		// an ss node; it means nothing on ss and there is nowhere to put it.
		"security": "mihomo's ss outbound has no TLS or security field",
		"alpn":     "mihomo's ss outbound has no TLS, so there is no ALPN to set",
	},
}

// proxyImportMuxNotHonoured is why `mux=1` is accepted and not acted on for the
// three protocols the exporter writes it for. mihomo does have a top-level
// `smux` block (adapter/parser.go), but it speaks sing-mux; the exporter's mux is
// v2ray's mux.cool. They are not the same wire protocol, so translating the flag
// would build a node that negotiates a multiplexer the server does not run.
const proxyImportMuxNotHonoured = "mihomo's multiplexer (smux / sing-mux) is not the v2ray mux the exporter means, so the flag is not translated"

// tolerateUnmapped decides what an unmapped query key means.
//
// Every product door passes true. It started as two answers for two callers
// -- a reader pasting one link was refused so the field got named, a
// subscription was tolerated because nobody is watching and upstream's own
// converter ignores query keys it does not know (common/convert/converter.go;
// the reader's ruling, 2026-08-25: aligning with upstream is the baseline,
// being stricter than it is a defect unless a platform requirement forces it,
// and nothing about an unknown query key touches the Network Extension
// guards). On 2026-08-28 the pasted link stopped refusing too: parse what
// parses, skip what does not, say what was skipped. The strict reading is
// kept only because provider_subscription_tolerance_test.go still asks for
// it; nothing a person reaches does. Tolerating still reports the field as
// not honoured, so this stays louder than upstream rather than quieter.
//
// The JSON body keys -- sing-box, v2ray, Shadowrocket/SIP008/SSD servers, the
// vmess base64-JSON body -- do not consult this flag at all since 2026-09-02:
// they are named and never refused (unmappedObjectKeys).
// unbuildableProxyImportPlugin names the plugin this build cannot construct, or
// returns "" when there is nothing to say.
//
// One predicate, read twice: here for the notice, and by the constructors for
// the decision to leave the plugin unset. Two copies of "can this be built"
// would be two answers the day one of them learns a new plugin.
// proxyImportPluginMode normalises a plugin's mode to the spelling mihomo
// accepts, and returns "" when there is no such spelling.
//
// Measured against adapter.ParseProxy rather than read off the source: simple
// obfs takes http and tls, v2ray-plugin takes websocket and nothing else -- not
// even `ws`, which is what exporters write. Case is folded because
// `OBFS-LOCAL;OBFS=HTTP` is the same plugin as `obfs-local;obfs=http` written
// by a different tool, and `ws` is mapped because it is the same transport
// under the name every other part of this format uses for it.
//
// A mode with no accepted spelling makes the plugin unbuildable. Writing it
// through would produce a node the kernel then refuses -- this tree emitting a
// value it knows will not load, which is the failure it spent the day removing
// in the other direction.
func proxyImportPluginMode(pluginName, raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(strings.ToLower(pluginName), "v2ray-plugin"):
		if mode == "ws" || mode == "websocket" {
			return "websocket"
		}
		return ""
	default:
		if mode == "http" || mode == "tls" {
			return mode
		}
		return ""
	}
}

func unbuildableProxyImportPlugin(canonicalType, raw string) string {
	if raw == "" {
		return ""
	}
	switch canonicalType {
	case "ss", "trojan", "snell":
	default:
		return ""
	}
	name, values, err := parseShadowrocketPlugin(raw)
	if err != nil {
		return "this importer build could not read the plugin specification"
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "v2ray-plugin") {
		if proxyImportPluginMode(name, firstQueryValue(values, "mode", "obfs")) == "" {
			return "mihomo's v2ray-plugin carries websocket only, so the node is imported without a plugin"
		}
		return ""
	}
	if strings.Contains(lower, "obfs") {
		// trojan carries obfs over websocket only; simple-obfs takes http or tls.
		// Either way a mode with no accepted spelling means no plugin, not no
		// node.
		if canonicalType == "trojan" {
			if mode := strings.ToLower(firstQueryValue(values, "obfs", "mode")); mode == "websocket" || mode == "ws" {
				return ""
			}
			return "mihomo's trojan carries obfs over websocket only, so the node is imported without it"
		}
		if proxyImportPluginMode(name, firstQueryValue(values, "obfs", "mode")) == "" {
			return "mihomo's simple-obfs carries http or tls only, so the node is imported without a plugin"
		}
		return ""
	}
	return "mihomo has no " + name + " plugin, so the node is imported without one"
}

func validateProxyShareLinkQueryFields(link string, capability proxyImportCapability, tolerateUnmapped bool) ([]string, error) {
	if capability.CanonicalType == "ssr" {
		return validateSSRShareLinkFields(link, tolerateUnmapped)
	}
	if capability.CanonicalType == "trusttunnel" {
		parsed, err := url.Parse(strings.TrimSpace(link))
		if err == nil && parsed.Hostname() == "" {
			return nil, nil // The raw query is the official base64url TLV payload.
		}
	}
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return nil, nil
	}
	normalizeShadowrocketRawQuery(parsed)
	allowed, exists := proxyImportQueryFieldLedger[capability.CanonicalType]
	if !exists {
		return nil, fmt.Errorf("hako: no query-field ledger for supported proxy type %q", capability.CanonicalType)
	}
	unhonoured := proxyImportUnhonouredFields[capability.CanonicalType]
	var notHonoured []string
	// The plugin is judged here rather than where it is built, because this is
	// the side of the parse that can say something. A name this build cannot
	// construct leaves the node without a plugin -- upstream's own answer -- and
	// silence there would hand back a node that looks whole and behaves
	// differently.
	if reason := unbuildableProxyImportPlugin(capability.CanonicalType, parsed.Query().Get("plugin")); reason != "" {
		notHonoured = append(notHonoured, capability.Scheme+".query.plugin: "+reason)
	}
	for key := range parsed.Query() {
		// The unhonourable table is consulted first, and the order is the whole
		// point. A key can be both registered and unhonourable: registered means
		// "this importer knows the key", unhonourable means "the outbound has
		// nowhere to put it". Judging the ledger first made the second table
		// unreachable for every key in both, which is exactly the population it
		// exists for -- nine such families were instead refusing the whole node
		// from inside their constructors.
		if reason, registered := unhonoured[key]; registered {
			notHonoured = append(notHonoured, capability.Scheme+".query."+key+": "+reason)
			continue
		}
		if _, ok := allowed[key]; ok {
			continue
		}
		if tolerateUnmapped {
			notHonoured = append(notHonoured, unmappedProxyImportFieldNotice(capability.Scheme+".query."+key))
			continue
		}
		return nil, unsupportedProxyImportField(
			capability.Scheme+".query."+key,
			"this importer build does not map that field",
		)
	}
	sort.Strings(notHonoured)
	return notHonoured, nil
}

// SSR keeps its own whitelist because its query lives inside the base64 body,
// and it tolerates an unlisted key for the reason every other scheme does.
//
// It was missed when the rest of the import surface stopped refusing over
// unmapped keys, which is what a second copy of a rule does: the rule moved and
// the copy did not. It is still a separate function -- the query is not where
// url.Parse would look for it -- but the tolerance is now the caller's decision
// rather than this function's.
func validateSSRShareLinkFields(link string, tolerateUnmapped bool) ([]string, error) {
	_, payload, ok := strings.Cut(strings.TrimSpace(link), "://")
	if !ok {
		return nil, nil
	}
	decoded, err := convert.TryDecodeBase64(payload)
	if err != nil {
		return nil, nil
	}
	_, rawQuery, ok := strings.Cut(string(decoded), "/?")
	if !ok {
		return nil, nil
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, nil
	}
	allowed := queryFieldSet("remarks", "group", "obfsparam", "protoparam")
	var notHonoured []string
	for key := range query {
		if _, ok := allowed[key]; ok {
			continue
		}
		if tolerateUnmapped {
			notHonoured = append(notHonoured, unmappedProxyImportFieldNotice("ssr.query."+key))
			continue
		}
		return nil, unsupportedProxyImportField(
			"ssr.query."+key,
			"the SSR outbound cannot represent that field",
		)
	}
	sort.Strings(notHonoured)
	return notHonoured, nil
}

func singletonProxy(proxy map[string]any, err error) ([]map[string]any, error) {
	if err != nil {
		return nil, err
	}
	return []map[string]any{proxy}, nil
}

// Hysteria 2 accepts a hopping list where a port would go -- "443,5000-6000" or
// a bare range -- and url.Parse refuses it, because a port must be numeric. This
// mirrors upstream's own splitHysteria2Ports (common/convert/v.go): the port
// becomes the first entry of the spec and the spec itself moves to mihomo's
// `ports` key, so the kernel stays the validator for the exact grammar. Reading
// it here rather than letting the upstream converter do it keeps the ledger able
// to grade the query, and keeps the two answers identical -- verified against
// TestConvertsV2Ray_hysteria2PortHopping.
//
// IPv6 literals are left alone, exactly as upstream leaves them: it returns
// early on any authority containing "]", so honouring them here would make the
// importer disagree with the core it feeds.
// proxyImportPortHoppingTypes are the outbounds whose option struct actually has
// a `ports` field (adapter/outbound/hysteria.go, hysteria2.go). Everything else
// can only use the first port of a range.
var proxyImportPortHoppingTypes = map[string]struct{}{"hysteria": {}, "hysteria2": {}}

// normalizeEncodedAuthorityPortRange rewrites a base64-wrapped authority whose
// endpoint carries a port range, leaving the wrapping intact.
func normalizeEncodedAuthorityPortRange(link string) (string, string, bool) {
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link, "", false
	}
	head, rest := link[:separator+3], link[separator+3:]
	authority, tail := rest, ""
	if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
		authority, tail = rest[:cut], rest[cut:]
	}
	decoded, err := convert.TryDecodeBase64(authority)
	if err != nil || !bytes.Contains(decoded, []byte("@")) {
		return link, "", false
	}
	credentials, hostPort, ok := strings.Cut(string(decoded), "@")
	if !ok {
		return link, "", false
	}
	rewritten, spec := splitHostPortRange(hostPort)
	if spec == "" {
		return link, "", false
	}
	return head + base64.RawURLEncoding.EncodeToString([]byte(credentials+"@"+rewritten)) + tail, spec, true
}

// splitHostPortRange takes the first port out of `host:START-END`, which is how
// the exporter writes a port range once the authority has been decoded. It
// returns the rewritten host:port and the range it found; an ordinary host:port
// comes back unchanged with an empty range.
func splitHostPortRange(hostPort string) (string, string) {
	if strings.Contains(hostPort, "]") {
		return hostPort, ""
	}
	colon := strings.LastIndex(hostPort, ":")
	if colon < 0 {
		return hostPort, ""
	}
	host, spec := hostPort[:colon], hostPort[colon+1:]
	cut := strings.IndexAny(spec, ",-")
	if cut <= 0 {
		return hostPort, ""
	}
	return host + ":" + spec[:cut], spec
}

// normalizeShareLinkPortRange lifts the exporter's port range out of the
// authority. Shadowrocket normalises `?mport=40000-50000` into `host:40000-50000`
// for every protocol alike, while url.Parse rejects that as a port -- so reading
// it per-protocol left six of seven refusing a link the exporter routinely emits.
// The range belongs to the authority, not to hysteria2.
//
// It returns the rewritten link and the range it found. Only hysteria and
// hysteria2 can act on the range; for the rest the first port is the node and the
// caller names the range as not honoured.
func normalizeShareLinkPortRange(link string, supportsHopping bool) (string, string, bool) {
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link, "", false
	}
	head, rest := link[:separator+3], link[separator+3:]
	authority, tail := rest, ""
	if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
		authority, tail = rest[:cut], rest[cut:]
	}
	userinfo := ""
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo, authority = authority[:at+1], authority[at+1:]
	}
	if strings.Contains(authority, "]") {
		return link, "", false
	}
	colon := strings.LastIndex(authority, ":")
	if colon < 0 {
		return link, "", false
	}
	host, spec := authority[:colon], authority[colon+1:]
	if !strings.ContainsAny(spec, ",-") {
		return link, "", false
	}
	first := spec
	if cut := strings.IndexAny(spec, ",-"); cut >= 0 {
		first = spec[:cut]
	}
	if first == "" {
		return link, "", false
	}
	path, query, fragment := "", "", ""
	if cut := strings.Index(tail, "#"); cut >= 0 {
		fragment, tail = tail[cut:], tail[:cut]
	}
	if cut := strings.Index(tail, "?"); cut >= 0 {
		path, query = tail[:cut], tail[cut+1:]
	} else {
		path = tail
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return link, "", false
	}
	// An explicit query spelling wins: the reader wrote it on purpose.
	if supportsHopping && firstQueryValue(values, "ports", "mport") == "" {
		values.Set("ports", spec)
	}
	rewritten := head + userinfo + host + ":" + first + path
	if encoded := values.Encode(); encoded != "" {
		rewritten += "?" + encoded
	}
	return rewritten + fragment, spec, true
}

// appendShareLinkQueryDefault adds a query key only when the link does not
// already carry it, so an explicit value from the exporter always wins.
func appendShareLinkQueryDefault(link, key, value string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return link
	}
	query := parsed.Query()
	if query.Get(key) != "" {
		return link
	}
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func normalizeProxyShareLinkDialect(link string, capability proxyImportCapability) (string, *url.URL, string, error) {
	var portRange string
	scheme := strings.ToLower(strings.TrimSpace(capability.Scheme))
	canonicalLink := normalizeProxyImportAlias(strings.TrimSpace(link), scheme, capability.CanonicalType)
	if scheme == "vless" {
		if normalized, ok := normalizeLegacyVlessLink(canonicalLink); ok {
			canonicalLink = normalized
		}
	}
	if scheme == "http" || scheme == "https" || scheme == "socks" || scheme == "socks5" || scheme == "socks5h" ||
		scheme == "ssocks" || scheme == "ssocks5" {
		if normalized, ok := normalizeEncodedProxyAuthority(canonicalLink); ok {
			canonicalLink = normalized
		}
	}
	if capability.CanonicalType == "mieru" {
		if normalized, ok := normalizeEncodedUserinfo(canonicalLink); ok {
			canonicalLink = normalized
		}
		// adapter/outbound/mieru.go rejects anything but TCP or UDP, and the
		// exporter drops the key from its own output -- it carries the value in
		// only one direction because TCP is the only transport it offers. Reading
		// the omission as "unset" refuses a link it produces by default.
		canonicalLink = appendShareLinkQueryDefault(canonicalLink, "transport", "TCP")
	}
	if scheme == "ssocks" || scheme == "ssocks5" {
		// The exporter spells "SOCKS5 over TLS" in the scheme, not in a query key:
		// it emits ssocks:// for both aliases and carries `tls=1` only when the
		// user typed it. The scheme is the statement, so the alias rewrite to
		// socks5:// has to carry it or the TLS half is lost with the spelling.
		canonicalLink = appendShareLinkQueryDefault(canonicalLink, "tls", "1")
	}
	if scheme == "ss" {
		// ss wraps its whole authority in base64, so the range is invisible to the
		// scheme-agnostic reader below and goes straight to the upstream converter,
		// which refuses it. Unwrap, take the first port, wrap again.
		if normalized, spec, ok := normalizeEncodedAuthorityPortRange(canonicalLink); ok {
			canonicalLink, portRange = normalized, spec
		}
	}
	// Every scheme, not just the hopping ones: the exporter writes the range into
	// the authority for all of them alike, and url.Parse refuses it as a port.
	_, supportsHopping := proxyImportPortHoppingTypes[capability.CanonicalType]
	if normalized, spec, ok := normalizeShareLinkPortRange(canonicalLink, supportsHopping); ok {
		canonicalLink = normalized
		if !supportsHopping {
			portRange = spec
		}
	}
	parsed, err := url.Parse(canonicalLink)
	if err != nil || parsed.Hostname() == "" {
		return "", nil, "", fmt.Errorf("hako: malformed %s proxy URI", scheme)
	}
	normalizeShadowrocketRawQuery(parsed)
	query := parsed.Query()
	// The exporter fills an unset field with `none` instead of omitting the key.
	// Left in, it reaches the kernel as a literal protocol or congestion-control
	// name; the snell spelling of the same habit refused the record outright.
	for _, key := range proxyImportUnsetPlaceholderKeys[capability.CanonicalType] {
		if strings.EqualFold(query.Get(key), "none") {
			query.Del(key)
		}
	}
	if parsed.Fragment == "" {
		parsed.Fragment = firstQueryValue(query, "title", "remark", "remarks", "name")
	}
	setQueryAlias(query, "sni", "peer", "serverName", "tlsServerName")
	setQueryAlias(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify")

	switch capability.CanonicalType {
	case "vmess", "vless":
		if query.Get("security") == "" {
			if firstQueryValue(query, "pbk", "publicKey") != "" {
				query.Set("security", "reality")
			} else if queryBoolean(query, "tls") {
				query.Set("security", "tls")
			}
		}
		if capability.CanonicalType == "vless" && query.Get("flow") == "" && query.Get("xtls") == "2" {
			query.Set("flow", "xtls-rprx-vision")
		}
		setQueryAlias(query, "fp", "fingerprint")
		// vmess and vless do not verify this field, so nothing is gained by
		// filtering it and a value the kernel accepts would be lost.
		setQueryAlias(query, "pcs", "hpkp")
		setUsableQueryAlias(query, "pbk", realityPublicKeyOrNothing, "publicKey")
		setQueryAlias(query, "sid", "shortId")
	case "hysteria":
		setQueryAlias(query, "peer", "sni", "serverName", "tlsServerName")
	case "hysteria2":
		setQueryAlias(query, "up", "upmbps")
		setQueryAlias(query, "down", "downmbps")
		setQueryAlias(query, "obfs-password", "obfsParam")
		setUsableQueryAlias(query, "pinSHA256", hysteria2CertificatePin, "hpkp", "fingerprint")
	case "tuic":
		setQueryAlias(query, "congestion_control", "proto", "congestion-controller")
		setQueryAlias(query, "udp_relay_mode", "udp-relay-mode", "udp")
	case "trojan":
		setQueryAlias(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify")
		setQueryAlias(query, "type", "proto", "network")
		if query.Get("type") == "" && strings.EqualFold(query.Get("obfs"), "websocket") {
			query.Set("type", "ws")
		}
	case "anytls":
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			query.Set("insecure", "1")
		}
	case "mieru":
		if len(query["port"]) == 0 && parsed.Port() != "" {
			query.Add("port", parsed.Port())
			parsed.Host = net.JoinHostPort(parsed.Hostname(), "")
			parsed.Host = strings.TrimSuffix(parsed.Host, ":")
		}
		if len(query["protocol"]) == 0 {
			if protocol := firstQueryValue(query, "proto", "transport"); protocol != "" {
				query.Add("protocol", strings.ToUpper(protocol))
			}
		} else {
			for index, protocol := range query["protocol"] {
				query["protocol"][index] = strings.ToUpper(protocol)
			}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), parsed, portRange, nil
}

// normalizeEncodedUserinfo unwraps a base64 `user:password` that the exporter
// wrote into the username position with an empty password after it. Upstream
// reads User.Username() and User.Password() raw, so the whole encoded pair became
// the username and the password came out empty -- the same shape as the authority
// prefix it writes for vless, one field over.
func normalizeEncodedUserinfo(link string) (string, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.User == nil {
		return link, false
	}
	if password, hasPassword := parsed.User.Password(); hasPassword && password != "" {
		return link, false
	}
	decoded, decodeErr := convert.TryDecodeBase64(parsed.User.Username())
	if decodeErr != nil {
		return link, false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" || password == "" {
		return link, false
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String(), true
}

func normalizeEncodedProxyAuthority(link string) (string, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" {
		return link, false
	}
	decoded, err := convert.TryDecodeBase64(parsed.Host)
	if err != nil {
		return link, false
	}
	// The question is whether what decoded is an authority, and the host-and-port
	// check below answers it. An `@` is only the half that appears when there are
	// credentials, and requiring it refused every unauthenticated socks node the
	// exporter writes -- it base64s `host:port` the same way it base64s
	// `user:pass@host:port`, and both are legal (socks.en.md lists username and
	// password as optional).
	authority, err := url.Parse(parsed.Scheme + "://" + string(decoded))
	if err != nil || authority.Hostname() == "" || authority.Port() == "" {
		return link, false
	}
	authority.RawQuery = parsed.RawQuery
	authority.Fragment = parsed.Fragment
	return authority.String(), true
}

func normalizeShadowrocketRawQuery(parsed *url.URL) {
	if parsed != nil && strings.Contains(parsed.RawQuery, ";") {
		parsed.RawQuery = strings.ReplaceAll(parsed.RawQuery, ";", "%3B")
	}
}

func parseLegacyVMessShareLink(link string) (map[string]any, string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || !strings.EqualFold(parsed.Scheme, "vmess") || parsed.Host == "" {
		return nil, "", false, nil
	}
	if decoded, decodeErr := convert.TryDecodeBase64(parsed.Host); decodeErr == nil {
		if trimmed := bytes.TrimSpace(decoded); len(trimmed) > 0 && trimmed[0] == '{' {
			// The JSON payload spelling belongs to another reader.
			return nil, "", false, nil
		}
	}
	cipher, uuid, hostPort, matched, splitErr := splitLegacyCredentialAuthority(parsed)
	if splitErr != nil {
		return nil, "", true, splitErr
	}
	if !matched {
		return nil, "", false, nil
	}
	if cipher == "" {
		cipher = "auto"
	}
	hostPort, droppedPorts := splitHostPortRange(hostPort)
	endpoint, err := url.Parse("vmess://" + url.User(uuid).String() + "@" + hostPort)
	if err != nil || endpoint.Hostname() == "" || endpoint.Port() == "" {
		return nil, "", true, fmt.Errorf("hako: legacy vmess authority has an invalid endpoint")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, "", true, fmt.Errorf("hako: legacy vmess authority has an invalid port")
	}
	query := parsed.Query()
	name := parsed.Fragment
	if name == "" {
		name = firstQueryValue(query, "remarks", "remark", "title")
	}
	if name == "" {
		name = endpoint.Hostname()
	}
	proxy := map[string]any{
		"name": name, "type": "vmess", "server": endpoint.Hostname(), "port": port,
		"uuid": uuid, "cipher": cipher, "alterId": 0, "udp": query.Get("udp") != "0",
	}
	if alterID := query.Get("alterId"); alterID != "" {
		value, parseErr := strconv.Atoi(alterID)
		if parseErr != nil {
			return nil, "", true, fmt.Errorf("hako: legacy vmess has an invalid alterId")
		}
		proxy["alterId"] = value
	}
	if tls := strings.ToLower(query.Get("tls")); tls == "1" || tls == "true" || tls == "tls" {
		proxy["tls"] = true
		if serverName := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); serverName != "" {
			proxy["servername"] = serverName
		}
	}
	applyTransportDialect(proxy, query)
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := firstQueryValue(query, "fp", "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey := realityPublicKeyOrNothing(firstQueryValue(query, "pbk", "publicKey")); publicKey != "" {
		proxy["tls"] = true
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   firstQueryValue(query, "sid", "shortId"),
		}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, droppedPorts, true, nil
}

// applyWebsocketDialect translates the one spelling Shadowrocket uses for
// websocket, whatever protocol carries it: obfs names the transport, obfsParam
// carries the Host header, path carries the path. It used to live inside the
// legacy VMess reader alone, so the same link imported as vmess got ws and as
// vless got tcp -- a node that looks complete and cannot connect. The dialect
// belongs to the exporter, not to one protocol's branch.
// applyTransportDialect maps the exporter's `obfs=` transport spelling onto the
// kernel's `network` plus its per-transport options. The exporter states the
// transport in `obfs` for every protocol that can carry one, so this is one
// reader for all of them -- and it covers every value it emits, not just
// websocket: grpc arrives the same way, with `path` holding the service name
// rather than a URL path.
func applyTransportDialect(proxy map[string]any, query url.Values) {
	obfs := strings.ToLower(query.Get("obfs"))
	if obfs == "" && query.Get("obfsParam") != "" {
		// The exporter drops `obfs=websocket` from its own canonical output and
		// leaves `obfsParam` and `path` behind, so requiring the key missed the
		// most common websocket node there is: one exported from Shadowrocket.
		obfs = "websocket"
	}
	switch obfs {
	case "websocket", "ws":
		proxy["network"] = "ws"
		headers := map[string]any{}
		if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
			headers["Host"] = host
		}
		proxy["ws-opts"] = map[string]any{
			"path":    query.Get("path"),
			"headers": headers,
		}
	case "grpc":
		proxy["network"] = "grpc"
		if name := firstQueryValue(query, "path", "serviceName", "grpc-service-name"); name != "" {
			proxy["grpc-opts"] = map[string]any{"grpc-service-name": name}
		}
	}
}

func applyProxyShareLinkDialect(proxy map[string]any, parsed *url.URL) error {
	query := parsed.Query()
	switch proxy["type"] {
	case "vmess", "vless":
		applyTransportDialect(proxy, query)
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			proxy["skip-cert-verify"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
			proxy["fingerprint"] = pin
		}
		// Neither the upstream converter nor this branch read these, so a node
		// exported with either came back without it -- accepted by the ledger,
		// dropped on the floor. `fingerprint` here is the uTLS profile the exporter
		// means, which is mihomo's `client-fingerprint`; its certificate pin
		// arrives as hpkp/pcs and is handled above.
		if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
			if _, present := proxy["alpn"]; !present {
				proxy["alpn"] = alpn
			}
		}
		if profile := firstQueryValue(query, "fp", "fingerprint", "client-fingerprint"); profile != "" {
			if _, present := proxy["client-fingerprint"]; !present {
				proxy["client-fingerprint"] = profile
			}
		}
	case "tuic":
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			proxy["skip-cert-verify"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pinSHA256", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
	case "trojan":
		applyTransportDialect(proxy, query)
		if publicKey := realityPublicKeyOrNothing(firstQueryValue(query, "pbk", "publicKey")); publicKey != "" {
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   firstQueryValue(query, "sid", "shortId"),
			}
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
			proxy["fingerprint"] = pin
		}
		if err := applyShadowrocketTrojanPlugin(proxy, query.Get("plugin")); err != nil {
			return err
		}
	case "ss":
		// `udp` is registered above but deliberately NOT read here, and the
		// distinction matters. Upstream sets ss["udp"] = true unconditionally
		// (common/convert/converter.go:452) and never looks at the query, so the
		// key carries no meaning on this protocol -- reading it would invent a
		// semantics upstream does not have, and reading it as a switch would let
		// `udp=0` turn off something upstream leaves on. Measured against
		// convert.ConvertsV2Ray for three shapes: absent, udp=0, and plain
		// trojan all come back with udp true on both sides.
		//
		// Registration alone is the right answer here: the key stops refusing
		// the link and changes nothing else. That is a third disposition beside
		// "honour it" and "refuse it" -- the field is simply not a field on this
		// protocol. Raised by the macOS lane while reading upstream's converter.
		// The exporter spells an ss obfuscation two ways, and upstream reads the
		// `plugin=` one only on the plain-authority path: an ss link whose whole
		// authority is base64 -- its default for ss -- reached the kernel with no
		// plugin at all, websocket or http alike. So both spellings are mapped here
		// and written onto the proxy, whatever path the authority took.
		if plugin := query.Get("plugin"); plugin != "" {
			name, values, err := parseShadowrocketPlugin(plugin)
			if err != nil {
				return err
			}
			allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path", "tls")
			if err := validateNestedQueryFields("ss.query.plugin", values, allowed); err != nil {
				return err
			}
			lowerName := strings.ToLower(name)
			switch {
			case strings.Contains(lowerName, "obfs"):
				// This overwrites whatever upstream's converter already put here
				// rather than deferring to it, and the reason is narrow:
				// upstream reads the plugin's subfields case sensitively
				// (common/convert/converter.go:303), so `OBFS=http` leaves it
				// writing an empty mode -- a node the kernel then refuses with
				// `obfs mode error:`. Deferring meant passing that through. What
				// is written here is normalised against what adapter.ParseProxy
				// accepts, so it is either usable or absent.
				mode := proxyImportPluginMode(name, firstQueryValue(values, "obfs", "mode"))
				if mode == "" {
					delete(proxy, "plugin")
					delete(proxy, "plugin-opts")
					break
				}
				proxy["plugin"] = "obfs"
				proxy["plugin-opts"] = map[string]any{
					"mode": mode,
					"host": firstQueryValue(values, "obfs-host", "host"),
				}
			case strings.Contains(lowerName, "v2ray-plugin"):
				{
					mode := proxyImportPluginMode(name, firstQueryValue(values, "mode", "obfs"))
					if mode == "" {
						delete(proxy, "plugin")
						delete(proxy, "plugin-opts")
						break
					}
					opts := map[string]any{
						"mode": mode,
						"host": firstQueryValue(values, "host", "obfs-host"),
					}
					if path := firstQueryValue(values, "path", "obfs-uri"); path != "" {
						opts["path"] = path
					}
					if queryBoolean(values, "tls") {
						opts["tls"] = true
					}
					proxy["plugin"] = "v2ray-plugin"
					proxy["plugin-opts"] = opts
				}
			default:
				// A plugin this build cannot construct leaves the node without
				// one, which is exactly what upstream does: its converter looks
				// the name up, finds nothing, and hands back a map with no
				// plugin key at all -- measured, and the kernel loads it. The
				// refusal here was stricter than the whole chain below it.
				//
				// The reader's ruling on 2026-08-28 settles the argument that
				// kept it: a node missing its obfs will not reach a server that
				// expects one, and that is true, but it is equally true of the
				// node upstream produces, and refusing costs the person a node
				// that would have worked whenever the plugin was junk an
				// exporter left behind. The field is named in the report.
				delete(proxy, "plugin")
				delete(proxy, "plugin-opts")
			}
		} else if obfs := strings.ToLower(query.Get("obfs")); obfs == "websocket" || obfs == "ws" {
			// The same websocket dialect vmess, vless and trojan already read
			// on ss it maps to v2ray-plugin, per upstream's ss.md.
			opts := map[string]any{"mode": "websocket"}
			if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
				opts["host"] = host
			}
			if path := query.Get("path"); path != "" {
				opts["path"] = path
			}
			proxy["plugin"] = "v2ray-plugin"
			proxy["plugin-opts"] = opts
		} else if obfs == "http" || obfs == "tls" {
			proxy["plugin"] = "obfs"
			opts := map[string]any{"mode": obfs}
			if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
				opts["host"] = host
			}
			proxy["plugin-opts"] = opts
		}
	case "hysteria":
		if auth := query.Get("auth"); auth != "" {
			proxy["auth_str"] = auth
		} else if parsed.User != nil && parsed.User.Username() != "" {
			proxy["auth_str"] = parsed.User.Username()
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pinSHA256", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
	case "hysteria2":
		if spec := firstQueryValue(query, "ports", "mport"); spec != "" {
			proxy["ports"] = spec
		}
		if hop := firstQueryValue(query, "hop-interval", "hopInterval"); hop != "" {
			proxy["hop-interval"] = hop
		}
	case "anytls":
		if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fingerprint := firstQueryValue(query, "fp"); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
	case "http":
		if strings.EqualFold(parsed.Scheme, "https") {
			proxy["tls"] = true
		}
		if sni := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); sni != "" {
			proxy["sni"] = sni
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
		// Same spelling, same meaning, same reason as socks5 below.
		if strings.EqualFold(firstQueryValue(query, "security"), "tls") {
			proxy["tls"] = true
		}
	case "socks5":
		// security=tls means the same thing as tls=1, and security=none means
		// the same as its absence. Reading only the boolean spelling accepted
		// the key and then dropped what it said, which is worse than refusing:
		// the node would import as plaintext and fail at dial time with nothing
		// pointing back at the link.
		if queryBoolean(query, "tls") || strings.EqualFold(firstQueryValue(query, "security"), "tls") {
			proxy["tls"] = true
		}
		if queryBoolean(query, "udp") {
			proxy["udp"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
	case "mieru":
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return nil
}

func applyShadowrocketTrojanPlugin(proxy map[string]any, raw string) error {
	if raw == "" {
		return nil
	}
	name, values, err := parseShadowrocketPlugin(raw)
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(name), "obfs") {
		// Same as ss: upstream drops the plugin key and the kernel loads the
		// node. Measured, not assumed. Returning here rather than falling
		// through matters -- the checks below read the plugin's own options,
		// which a plugin that is not obfs does not have.
		return nil
	}
	allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path")
	if err := validateNestedQueryFields("trojan.query.plugin", values, allowed); err != nil {
		return err
	}
	mode := strings.ToLower(firstQueryValue(values, "obfs", "mode"))
	if mode != "websocket" && mode != "ws" {
		// mihomo's trojan has no simple-obfs transport, only websocket, so an
		// obfs mode that is not websocket has nowhere to go -- and refusing over
		// it costs a node upstream imports. The plugin is left off and the field
		// is named, the same answer as an unbuildable plugin name.
		return nil
	}
	proxy["network"] = "ws"
	proxy["ws-opts"] = map[string]any{
		"path": firstQueryValue(values, "obfs-uri", "path"),
		"headers": map[string]any{
			"Host": firstQueryValue(values, "obfs-host", "host"),
		},
	}
	return nil
}

// parseShadowrocketPlugin reads `name;key=value;key=value`, and folds the
// subfield names to lower case.
//
// Exporters do not agree on case: `obfs-local;obfs=http`,
// `OBFS-LOCAL;OBFS=HTTP` and `Obfs-Local;Obfs=Http` are the same plugin
// written three ways, and this build recognised the plugin name in all three
// (it already lowered that) and then refused the record over the subfield
// spelling. Upstream never gets that far -- its own plugin lookup is case
// sensitive, so an upper-case name simply drops the plugin and the node loads
// without one -- which means refusing was worse than upstream on input
// upstream handles, while mapping it is better than upstream on the same
// input. The values are left exactly as written; only the names are folded,
// because a name is a spelling and a value is the person's data.
func parseShadowrocketPlugin(raw string) (string, url.Values, error) {
	values, err := url.ParseQuery("pluginName=" + strings.ReplaceAll(raw, ";", "&"))
	if err != nil {
		return "", nil, fmt.Errorf("hako: malformed plugin parameter: %w", err)
	}
	name := values.Get("pluginName")
	if name == "" {
		return "", nil, fmt.Errorf("hako: plugin parameter has no name")
	}
	folded := make(url.Values, len(values))
	for key, value := range values {
		folded[strings.ToLower(key)] = value
	}
	return name, folded, nil
}

// validateNestedQueryFields no longer refuses over a subfield it does not know,
// for the reason nothing else on this surface does: upstream drops the whole
// plugin rather than reading its parts, so a subfield spelling cannot be worth
// a node here when it is worth nothing there.
//
// It is kept as a function rather than deleted at the call sites because the
// plugin's own name and mode are still judged -- see
// unbuildableProxyImportPlugin -- and this is where a future subfield check
// would go if one is ever needed for a reason other than tidiness.
func validateNestedQueryFields(prefix string, values url.Values, allowed map[string]struct{}) error {
	return nil
}

// proxyImportUnsetPlaceholderKeys lists, per canonical type, the query keys whose
// value space does not contain "none", so a `none` there is the exporter saying
// the user set nothing. Keys where `none` is a real value -- vless `encryption`,
// `obfs` -- are deliberately absent.
var proxyImportUnsetPlaceholderKeys = map[string][]string{
	"hysteria": {"protocol"},
	"tuic":     {"congestion_control", "congestion-controller"},
	"snell":    {"version", "v"},
}

// firstConfiguredQueryValue is firstQueryValue for keys whose value space does
// not contain the word "none". The exporter fills an unset field with `none`
// rather than omitting the key -- `version=none` on a snell node it exported with
// no version set, `protocol=none` on hysteria, `congestion_control=none` on tuic
// -- so reading it literally turns "the user set nothing" into a value. It cost a
// whole snell record: strconv.Atoi("none") refused the link Shadowrocket produces
// by default.
//
// This is deliberately not applied everywhere: `encryption=none` on vless and
// `obfs=none` are real values, and blanking them would be the same mistake in the
// other direction.
func firstConfiguredQueryValue(query url.Values, keys ...string) string {
	if value := firstQueryValue(query, keys...); !strings.EqualFold(value, "none") {
		return value
	}
	return ""
}

func firstQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func setQueryAlias(query url.Values, canonical string, aliases ...string) {
	setUsableQueryAlias(query, canonical, nil, aliases...)
}

// setUsableQueryAlias copies a spelling into the key upstream reads, and
// declines to copy a value that key cannot use.
//
// Normalising an alias is this tree's own act, and it is the act that has to be
// judged. `setUsableQueryAlias(query, "pinSHA256", hysteria2CertificatePin, "hpkp", "fingerprint")` copies
// whatever an exporter wrote as `fingerprint` into the certificate-pin key that
// upstream's converter reads -- so a hysteria2 link carrying the uTLS name
// `fingerprint=chrome`, which upstream ignores entirely and imports fine, came
// out of here with `pinSHA256=chrome` and was refused by the outbound. Upstream
// never wrote that; we did, on the way past.
//
// The check runs at the copy rather than at the read because by the time
// upstream's converter has the query, the alias is indistinguishable from a
// value the person wrote themselves.
func setUsableQueryAlias(query url.Values, canonical string, usable func(string) string, aliases ...string) {
	if query.Get(canonical) != "" {
		return
	}
	value := firstQueryValue(query, aliases...)
	if usable != nil {
		value = usable(value)
	}
	if value != "" {
		query.Set(canonical, value)
	}
}

func queryBoolean(query url.Values, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(query.Get(key)))
		switch value {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func parseRequiredProxyURL(link, expectedType string) (*url.URL, int, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, 0, fmt.Errorf("hako: malformed %s proxy URI", expectedType)
	}
	normalizeShadowrocketRawQuery(parsed)
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("hako: invalid %s proxy port", expectedType)
	}
	return parsed, port, nil
}

func proxyName(parsed *url.URL) string {
	query := parsed.Query()
	if parsed.Fragment != "" {
		return parsed.Fragment
	}
	if name := firstQueryValue(query, "title", "remark", "remarks", "name", "profile"); name != "" {
		return name
	}
	if parsed.Port() != "" {
		return net.JoinHostPort(parsed.Hostname(), parsed.Port())
	}
	return parsed.Hostname()
}

func parseSnellShareLink(link string) (map[string]any, error) {
	// The exporter writes snell two ways: `base64(cipher:psk)@host:port`, and --
	// when the link came in with `psk=` -- the whole authority in base64 with the
	// password position empty and the key moved to `pbk=`. Unwrap the second so
	// url.Parse sees a host and port at all.
	if normalized, ok := normalizeEncodedProxyAuthority(link); ok {
		link = normalized
	}
	parsed, port, err := parseRequiredProxyURL(link, "snell")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	psk := parsed.User.Username()
	if password, ok := parsed.User.Password(); ok {
		psk = password
	}
	if decoded, decodeErr := convert.TryDecodeBase64(psk); decodeErr == nil {
		if _, password, ok := strings.Cut(string(decoded), ":"); ok {
			// Taken even when empty: the exporter writes `cipher:` with nothing
			// after it for a node whose key it did not carry, and keeping the
			// undecoded base64 as the key made that node import with a psk that is
			// the word "chacha20-ietf-poly1305:" in base64. An empty key falls
			// through to the query spellings below, which is the honest answer.
			psk = password
		}
	}
	if psk == "" {
		// The exporter carries the PSK as `pbk=` when a link was imported with
		// `psk=` -- its own output for the same node -- and leaves the authority's
		// password position empty. `pbk` is the reality public-key spelling on
		// vless; on snell it is the only place the key survives.
		psk = firstQueryValue(query, "psk", "password", "pbk")
	}
	if psk == "" {
		return nil, fmt.Errorf("hako: snell proxy is missing its PSK")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "snell", "server": parsed.Hostname(),
		"port": port, "psk": psk,
	}
	if version := firstConfiguredQueryValue(query, "version", "v"); version != "" {
		value, parseErr := strconv.Atoi(version)
		if parseErr != nil {
			return nil, fmt.Errorf("hako: invalid snell version %q", version)
		}
		proxy["version"] = value
	}
	if queryBoolean(query, "udp") {
		proxy["udp"] = true
	}
	if queryBoolean(query, "reuse") {
		proxy["reuse"] = true
	}
	mode := firstQueryValue(query, "obfs", "obfs-mode")
	host := firstQueryValue(query, "obfsParam", "obfs-host", "peer", "sni")
	if plugin := query.Get("plugin"); plugin != "" {
		name, values, parseErr := parseShadowrocketPlugin(plugin)
		if parseErr != nil {
			return nil, parseErr
		}
		if !strings.Contains(strings.ToLower(name), "obfs") {
			// snell share links are not something upstream's converter reads at
			// all, so there is no upstream answer to match here. This follows ss
			// and trojan rather than inventing a third behaviour for the same
			// situation.
			return proxy, nil
		}
		allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path")
		if parseErr := validateNestedQueryFields("snell.query.plugin", values, allowed); parseErr != nil {
			return nil, parseErr
		}
		mode = firstQueryValue(values, "obfs", "mode")
		host = firstQueryValue(values, "obfs-host", "host")
		if path := firstQueryValue(values, "obfs-uri", "path"); path != "" && path != "/" {
			return nil, unsupportedProxyImportField(
				"snell.query.plugin.obfs-uri",
				"the Core Snell simple-obfs transport cannot represent a custom URI",
			)
		}
	}
	if mode != "" {
		proxy["obfs-opts"] = map[string]any{
			"mode": mode,
			"host": host,
		}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	// `pbk` is not in this list: on vless it is the reality public key, but on
	// snell it is where the exporter carries the PSK, and it was taken as the key
	// above. `alpn` and `security` are not here either: the exporter writes them
	// onto a snell node when TLS parameters were fed to it, and mihomo's snell
	// carries no TLS at all -- they are registered as not honoured, not
	// grounds to refuse the node.
	return proxy, nil
}

func parseSSHShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "ssh")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	if value := query.Get("user"); value != "" {
		username = value
	}
	if value := query.Get("password"); value != "" {
		password = value
	}
	if username == "" {
		return nil, fmt.Errorf("hako: ssh proxy is missing its username")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "ssh", "server": parsed.Hostname(),
		"port": port, "username": username,
	}
	if password != "" {
		proxy["password"] = password
	}
	if privateKey := firstQueryValue(query, "private-key", "privateKey", "pk"); privateKey != "" {
		proxy["private-key"] = privateKey
	}
	if passphrase := firstQueryValue(query, "private-key-passphrase", "privateKeyPassphrase", "pp"); passphrase != "" {
		proxy["private-key-passphrase"] = passphrase
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseWireGuardShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "wireguard")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	privateKey := firstQueryValue(query, "privateKey", "private-key")
	publicKey := firstQueryValue(query, "publicKey", "public-key")
	ipv4, ipv6 := splitIPValues(query["ip"])
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("hako: wireguard proxy requires privateKey, publicKey and ip")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "wireguard", "server": parsed.Hostname(), "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if psk := firstQueryValue(query, "presharedKey", "preSharedKey", "pre-shared-key", "preshared-key", "password"); psk != "" {
		proxy["pre-shared-key"] = psk
	}
	if value := query.Get("mtu"); value != "" {
		mtu, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("hako: invalid wireguard mtu %q", value)
		}
		proxy["mtu"] = mtu
	}
	if value := firstQueryValue(query, "keepalive", "persistent-keepalive"); value != "" {
		keepalive, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("hako: invalid wireguard keepalive %q", value)
		}
		proxy["persistent-keepalive"] = keepalive
	}
	if dns := splitListValues(query["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if reserved := firstQueryValue(query, "reserved"); reserved != "" {
		values, parseErr := parseReservedBytes(reserved)
		if parseErr != nil {
			return nil, parseErr
		}
		proxy["reserved"] = values
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func splitIPValues(values []string) (string, string) {
	var ipv4, ipv6 string
	for _, value := range splitListValues(values) {
		address := strings.TrimSpace(strings.SplitN(value, "/", 2)[0])
		if strings.Contains(address, ":") && ipv6 == "" {
			ipv6 = value
		} else if ipv4 == "" {
			ipv4 = value
		}
	}
	return ipv4, ipv6
}

func splitListValues(values []string) []string {
	var result []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				result = append(result, item)
			}
		}
	}
	return result
}

func parseReservedBytes(value string) ([]uint8, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '-' || r == ' ' })
	if len(parts) != 3 {
		return nil, fmt.Errorf("hako: wireguard reserved must contain three bytes")
	}
	result := make([]uint8, 3)
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("hako: invalid wireguard reserved byte %q", part)
		}
		result[index] = uint8(number)
	}
	return result, nil
}

func parseMasqueShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "masque")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	privateKey := firstQueryValue(query, "privateKey", "private-key")
	publicKey := firstQueryValue(query, "publicKey", "public-key")
	ipv4, ipv6 := splitIPValues(query["ip"])
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("hako: masque proxy requires privateKey, publicKey and ip")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "masque", "server": parsed.Hostname(), "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if value := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); value != "" {
		proxy["sni"] = value
	}
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if value := query.Get("uri"); value != "" {
		proxy["uri"] = value
	}
	if value := query.Get("mtu"); value != "" {
		mtu, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("hako: invalid masque mtu %q", value)
		}
		proxy["mtu"] = mtu
	}
	if protocol := firstQueryValue(query, "proto", "network"); protocol == "h2" || protocol == "h3-l4proxy" {
		proxy["network"] = protocol
	}
	if dns := splitListValues(query["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseTrustTunnelShareLink(link string) (map[string]any, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || !strings.EqualFold(parsed.Scheme, "tt") {
		return nil, fmt.Errorf("hako: malformed trusttunnel proxy URI")
	}
	if parsed.Hostname() != "" {
		return parseTrustTunnelAuthorityLink(parsed)
	}
	payload := parsed.RawQuery
	if payload == "" {
		return nil, fmt.Errorf("hako: trusttunnel deep link is missing its TLV payload")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("hako: decode trusttunnel deep link: %w", err)
	}
	return parseTrustTunnelTLV(decoded)
}

func parseTrustTunnelAuthorityLink(parsed *url.URL) (map[string]any, error) {
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("hako: invalid trusttunnel proxy port")
	}
	query := parsed.Query()
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "trusttunnel", "server": parsed.Hostname(), "port": port,
		"username": username, "password": password, "udp": true,
	}
	if sni := firstQueryValue(query, "peer", "sni", "hostname"); sni != "" {
		proxy["sni"] = sni
	}
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if strings.EqualFold(firstQueryValue(query, "proto", "protocol"), "h3") {
		proxy["quic"] = true
		proxy["alpn"] = []string{"h3"}
	} else {
		proxy["alpn"] = []string{"h2"}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseTrustTunnelTLV(payload []byte) (map[string]any, error) {
	fields := make(map[uint64][][]byte)
	for len(payload) > 0 {
		tag, consumed, err := readTLSVarint(payload)
		if err != nil {
			return nil, fmt.Errorf("hako: trusttunnel TLV tag: %w", err)
		}
		payload = payload[consumed:]
		length, consumed, err := readTLSVarint(payload)
		if err != nil {
			return nil, fmt.Errorf("hako: trusttunnel TLV length: %w", err)
		}
		payload = payload[consumed:]
		if length > uint64(len(payload)) {
			return nil, fmt.Errorf("hako: truncated trusttunnel TLV value")
		}
		fields[tag] = append(fields[tag], append([]byte(nil), payload[:int(length)]...))
		payload = payload[int(length):]
	}
	knownTags := map[uint64]struct{}{
		0x00: {}, 0x01: {}, 0x02: {}, 0x03: {}, 0x05: {}, 0x06: {}, 0x07: {},
		0x08: {}, 0x09: {}, 0x0a: {}, 0x0b: {}, 0x0c: {}, 0x0d: {},
	}
	for tag := range fields {
		if _, ok := knownTags[tag]; !ok {
			return nil, unsupportedProxyImportField(
				fmt.Sprintf("trusttunnel.tlv.0x%x", tag),
				"unknown TrustTunnel TLV fields are not silently discarded",
			)
		}
	}
	if versionValues := fields[0x00]; len(versionValues) > 0 {
		version, _, err := readTLSVarint(versionValues[len(versionValues)-1])
		if err != nil || version > 1 {
			return nil, fmt.Errorf("hako: unsupported trusttunnel deep-link version")
		}
	}
	hostname := lastTLVString(fields[0x01])
	addresses := fields[0x02]
	username := lastTLVString(fields[0x05])
	password := lastTLVString(fields[0x06])
	if hostname == "" || len(addresses) == 0 || username == "" || password == "" {
		return nil, fmt.Errorf("hako: trusttunnel deep link is missing a required field")
	}
	if len(addresses) != 1 {
		return nil, unsupportedProxyImportField(
			"addresses", "this Core outbound can represent exactly one TrustTunnel endpoint",
		)
	}
	server, portText, err := net.SplitHostPort(string(addresses[0]))
	if err != nil {
		return nil, fmt.Errorf("hako: invalid trusttunnel address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("hako: invalid trusttunnel port")
	}
	if len(fields[0x08]) > 0 && !tlvBool(fields[0x07]) {
		return nil, unsupportedProxyImportField(
			"certificate", "this Core outbound cannot represent the deep link's pinned root chain",
		)
	}
	if tlvBool(fields[0x0a]) {
		return nil, unsupportedProxyImportField(
			"anti_dpi", "this Core outbound has no TrustTunnel anti-DPI option",
		)
	}
	if len(fields[0x0b]) > 0 {
		return nil, unsupportedProxyImportField(
			"client_random_prefix", "this Core outbound has no TLS client-random prefix option",
		)
	}
	if len(fields[0x0d]) > 0 {
		return nil, unsupportedProxyImportField(
			"dns_upstreams", "this Core outbound cannot attach per-node DNS upstreams",
		)
	}
	name := lastTLVString(fields[0x0c])
	if name == "" {
		name = hostname
	}
	proxy := map[string]any{
		"name": name, "type": "trusttunnel", "server": server, "port": port,
		"username": username, "password": password, "sni": hostname, "udp": true,
		"skip-cert-verify": tlvBool(fields[0x07]),
	}
	if customSNI := lastTLVString(fields[0x03]); customSNI != "" {
		proxy["sni"] = customSNI
	}
	protocol := uint64(1)
	if values := fields[0x09]; len(values) > 0 {
		parsed, consumed, parseErr := readTLSVarint(values[len(values)-1])
		if parseErr != nil || consumed != len(values[len(values)-1]) {
			return nil, fmt.Errorf("hako: invalid trusttunnel upstream_protocol")
		}
		protocol = parsed
	}
	if protocol != 1 && protocol != 2 {
		return nil, unsupportedProxyImportField(
			"upstream_protocol", fmt.Sprintf("unknown value %d", protocol),
		)
	}
	if protocol == 2 {
		proxy["quic"] = true
		proxy["alpn"] = []string{"h3"}
	} else {
		proxy["alpn"] = []string{"h2"}
	}
	return proxy, nil
}

func lastTLVString(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[len(values)-1])
}

func tlvBool(values [][]byte) bool {
	return len(values) > 0 && len(values[len(values)-1]) == 1 && values[len(values)-1][0] == 1
}

func readTLSVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("missing varint")
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, fmt.Errorf("truncated varint")
	}
	var value uint64
	switch size {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(binary.BigEndian.Uint16(data[:2]) & 0x3fff)
	case 4:
		value = uint64(binary.BigEndian.Uint32(data[:4]) & 0x3fffffff)
	case 8:
		value = binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff
	}
	return value, size, nil
}

func normalizeLegacyVlessPayload(payload []byte) []byte {
	text := string(payload)
	if !strings.Contains(text, "://") {
		if decoded, err := convert.TryDecodeBase64(strings.TrimSpace(text)); err == nil {
			text = string(decoded)
		}
	}
	lines := strings.Split(text, "\n")
	changed := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(strings.ToLower(trimmed), "vless://") {
			continue
		}
		normalized, ok := normalizeLegacyVlessLink(trimmed)
		if !ok {
			continue
		}
		lines[index] = normalized
		changed = true
	}
	if !changed {
		return []byte(text)
	}
	return []byte(strings.Join(lines, "\n"))
}

// splitLegacyCredentialAuthority reads the `method:id@host:port` authority that
// Shadowrocket and older clients emit for both vmess and vless. It arrives in two
// spellings -- base64-wrapped in the host, or plain, in which case url.Parse has
// already moved `method:id` into User -- and each protocol used to read it in its
// own function, so fixing one left the other reading the method half as the id
// . One reader, both protocols, both spellings.
//
// `matched` separates "not this dialect" from "this dialect, malformed": the
// wrapped spelling is an authoritative signature, so a broken one has to be an
// error rather than a silent fall-through to a parser that would build a node
// that looks complete and cannot connect.
func splitLegacyCredentialAuthority(parsed *url.URL) (method, id, hostPort string, matched bool, err error) {
	var methodAndID string
	if decoded, decodeErr := convert.TryDecodeBase64(parsed.Host); decodeErr == nil {
		var ok bool
		methodAndID, hostPort, ok = strings.Cut(string(decoded), "@")
		if !ok {
			return "", "", "", true, fmt.Errorf("hako: legacy %s authority is missing its endpoint", parsed.Scheme)
		}
	} else if parsed.User != nil {
		password, hasPassword := parsed.User.Password()
		if !hasPassword {
			// `scheme://id@host:port` is the modern spelling, not this dialect.
			return "", "", "", false, nil
		}
		methodAndID, hostPort = parsed.User.Username()+":"+password, parsed.Host
	} else {
		return "", "", "", false, nil
	}
	// The exporter writes three different things in the position before the colon
	// -- `auto:` (its vmess cipher name, reused), `none:`, and an empty string --
	// and also omits the position entirely. All four are the same node: vless has
	// no encryption negotiation, so that slot is a placeholder, and for vmess an
	// absent cipher means the default. Only the id is required. Splitting on the
	// last colon keeps a future value that contains one from eating the id.
	if separator := strings.LastIndex(methodAndID, ":"); separator >= 0 {
		method, id = methodAndID[:separator], methodAndID[separator+1:]
	} else {
		method, id = "", methodAndID
	}
	if id == "" {
		return "", "", "", true, fmt.Errorf("hako: legacy %s authority is missing its UUID", parsed.Scheme)
	}
	return method, id, hostPort, true, nil
}

// vlessEncryptionIsConstructible mirrors transport/vless/encryption.NewClient:
// the kernel accepts an empty string, `none`, and the mlkem768x25519plus family,
// and rejects everything else. Shadowrocket puts `auto` there -- a vmess cipher
// name -- so passing the slot through verbatim turned its default vless export
// into a refusal over a field vless does not negotiate at all.
func vlessEncryptionIsConstructible(encryption string) bool {
	switch encryption {
	case "", "none":
		return true
	}
	return strings.HasPrefix(encryption, "mlkem768x25519plus.")
}

// normalizeLegacyVlessLink handles the authority dialect emitted by
// Shadowrocket and older clients:
//
//	vless://base64("none:uuid@host:port")?type=tcp#name
//
// The decoded bytes are an authority, not a hostname. Reparse all four pieces
// so userinfo can never leak into the server field.
func normalizeLegacyVlessLink(link string) (string, bool) {
	parsed, err := url.Parse(link)
	if err != nil || !strings.EqualFold(parsed.Scheme, "vless") || parsed.Host == "" {
		return link, false
	}
	method, id, hostPort, matched, splitErr := splitLegacyCredentialAuthority(parsed)
	if !matched || splitErr != nil {
		return link, false
	}
	firstPortHostPort, portRange := splitHostPortRange(hostPort)
	authority, err := url.Parse("vless://" + url.User(id).String() + "@" + firstPortHostPort)
	if err != nil || authority.Hostname() == "" || authority.Port() == "" {
		return link, false
	}
	query := parsed.Query()
	if query.Get("encryption") == "" && method != "" && vlessEncryptionIsConstructible(method) {
		query.Set("encryption", method)
	}
	authority.RawQuery = query.Encode()
	authority.Fragment = parsed.Fragment
	rebuilt := authority.String()
	if portRange != "" {
		// The range goes back into the authority rather than being dropped here:
		// the scheme-agnostic reader downstream owns both taking the first port and
		// naming the range it could not honour, so this decoder must not silently
		// consume it. The first port was only borrowed to get past url.Parse.
		rebuilt = strings.Replace(rebuilt, firstPortHostPort, strings.TrimSuffix(firstPortHostPort[:strings.LastIndex(firstPortHostPort, ":")+1], "")+portRange, 1)
	}
	return rebuilt, true
}
