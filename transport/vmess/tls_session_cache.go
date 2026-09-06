package vmess

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/TokenPLS/Hako/component/ech"

	"github.com/TokenPLS/Hako/common/lru"

	"github.com/metacubex/tls"
)

// Session caches for the TLS outbounds that build their config inside the per-flow dial:
// trojan, vless, vmess, shadow-tls and the shadowsocks v2ray/gost plugins. Without a
// cache metacubex/tls disables resumption, so every flow paid a full handshake and a
// certificate verification -- on iOS an XPC round trip to trustd per flow.
//
// Resumption needs a long-lived cache, not a long-lived config, so rebuilding the config
// per dial is fine as long as it finds the same cache each time.
//
// The BUCKETING is not what an earlier version of this comment claimed. metacubex/tls
// keys its cache on config.ServerName alone, falling back to the remote address
// (handshake_client.go clientSessionCacheKey), so one process-wide cache would let two
// outbounds at the same server name trade sessions. But the specific downgrade that was
// used to justify bucketing -- an unverified session being resumed by a config that must
// verify -- is already refused upstream: loadSession returns no session when the cached
// one has no verified chains and the current config does not set InsecureSkipVerify, with
// the comment "The original connection had InsecureSkipVerify, while this doesn't". That
// claim was wrong and is corrected here rather than left standing.
//
// Bucketing is still right, for reasons that survive: a session carries the ALPN that was
// negotiated with it, differently pinned configs at one name are not interchangeable, and
// a session established through one ECH front is useless to another. Those are protocol
// correctness and wasted-handshake concerns, not a verification bypass.
//
// Pinned configurations gain nothing from any of this -- ca.GetTLSConfig sets
// InsecureSkipVerify for fingerprint and name-cert-verify, and metacubex/tls then skips
// chain building entirely -- but they still get their own bucket, because the correctness
// of the bucketing must not depend on knowing which configurations happen to benefit.
const sessionCacheBuckets = 256

var sessionCaches = lru.New[string, tls.ClientSessionCache](
	lru.WithSize[string, tls.ClientSessionCache](sessionCacheBuckets),
)

// sessionCacheFor returns the cache belonging to this config's security identity,
// creating it on first use. Bounded: a provider that rotates hostnames evicts the oldest
// bucket rather than growing without limit, and an evicted bucket only costs one full
// handshake to re-establish.
func sessionCacheFor(cfg *TLSConfig) tls.ClientSessionCache {
	cache, _ := sessionCaches.GetOrStore(sessionCacheIdentity(cfg), func() tls.ClientSessionCache {
		return tls.NewLRUClientSessionCache(0)
	})
	return cache
}

// sessionCacheIdentity is every field a resumed handshake would let a config skip or
// reinterpret. Anything that changes what the peer is, how it is authenticated, or what
// protocol was negotiated has to be in here; adding a field to TLSConfig that affects any
// of those means adding it here too.
//
// Lengths are written before values so no combination of contents can be confused for a
// different combination of fields.
func sessionCacheIdentity(cfg *TLSConfig) string {
	var identity strings.Builder
	writeField := func(value string) {
		identity.WriteString(strconv.Itoa(len(value)))
		identity.WriteByte(':')
		identity.WriteString(value)
		identity.WriteByte('|')
	}

	writeField(cfg.Host)
	writeField(strconv.FormatBool(cfg.SkipCertVerify))
	writeField(cfg.NameCertVerify)
	writeField(cfg.FingerPrint)
	writeField(cfg.Certificate)
	writeField(cfg.PrivateKey)
	// ECH identity, not merely presence. The resolved ECH configuration comes from a
	// resolver invoked AFTER this point, so its contents cannot be keyed here -- but the
	// *ech.Config is built once per outbound, so its address distinguishes two outbounds
	// that front the same server name through different ECH endpoints. Without this they
	// shared a bucket and, because metacubex/tls indexes by ServerName alone, each would
	// overwrite the other's ticket and both would keep doing full handshakes.
	writeField(echIdentity(cfg.ECH))
	identity.WriteString(strconv.Itoa(len(cfg.NextProtos)))
	identity.WriteByte(':')
	for _, protocol := range cfg.NextProtos {
		writeField(protocol)
	}
	return identity.String()
}

// echIdentity distinguishes ECH configurations by the identity of the per-outbound config
// object. "absent" for nil so a missing ECH config cannot collide with a pointer value.
func echIdentity(config *ech.Config) string {
	if config == nil {
		return "absent"
	}
	return "0x" + strconv.FormatUint(uint64(reflect.ValueOf(config).Pointer()), 16)
}
