package shadowquic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/jls-quic-go"
)

const (
	quicVersionProbeTimeout = time.Second
	quicVersionProbeSize    = 1200
	quicVersionProbeVersion = quic.Version(0x0a0a0a0a) // reserved version used to elicit Version Negotiation
	quicVersionGrease       = quic.Version(0x0a1a2a3a)
	quicVersionDraft29      = quic.Version(0xff00001d)
	quicVersionDraft30      = quic.Version(0xff00001e)
	quicVersionDraft31      = quic.Version(0xff00001f)
	quicVersionDraft32      = quic.Version(0xff000020)
	quicVersionDraft33      = quic.Version(0xff000021)
	quicVersionDraft34      = quic.Version(0xff000022)
)

var defaultQUICVersionNegotiationVersions = []quic.Version{
	quicVersionGrease,
	quic.Version1,
	quicVersionDraft29,
	quicVersionDraft30,
	quicVersionDraft31,
	quicVersionDraft32,
	quicVersionDraft33,
	quicVersionDraft34,
}

type QUICVersionProfileProvider func() ([]quic.Version, []quic.Version)

func DefaultQUICVersions() []quic.Version {
	return []quic.Version{quic.Version1}
}

func DefaultQUICVersionNegotiationVersions() []quic.Version {
	return CloneQUICVersions(defaultQUICVersionNegotiationVersions)
}

func ResolveQUICVersionProfile(versions []string, upstreamAddr string, upstreamProbe bool, dialer quic.JLSPacketDialer, logf func(string, ...any)) ([]quic.Version, []quic.Version, QUICVersionProfileProvider, error) {
	supported := DefaultQUICVersions()
	versionNegotiation := DefaultQUICVersionNegotiationVersions()

	if len(versions) > 0 {
		var err error
		supported, versionNegotiation, err = ParseQUICVersionProfile(versions)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if upstreamAddr == "" {
		return supported, versionNegotiation, nil, nil
	}
	if !upstreamProbe {
		return supported, versionNegotiation, nil, nil
	}
	if dialer == nil {
		return nil, nil, nil, errors.New("shadowquic: QUIC version probe dialer is nil")
	}

	provider := NewLazyQUICVersionProfile(upstreamAddr, dialer, supported, versionNegotiation, func(err error) {
		if logf != nil {
			logf("ShadowQuic JLS upstream QUIC version probe failed: %s", err)
		}
	})
	return supported, versionNegotiation, provider, nil
}

func ParseQUICVersionProfile(values []string) ([]quic.Version, []quic.Version, error) {
	versions := make([]quic.Version, 0, len(values))
	for _, value := range values {
		version, err := ParseQUICVersion(value)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, version)
	}
	supported, versionNegotiation := NormalizeQUICVersionProfile(versions)
	return supported, versionNegotiation, nil
}

func NewLazyQUICVersionProfile(address string, dialer quic.JLSPacketDialer, fallbackSupported, fallbackVersionNegotiation []quic.Version, onProbeError func(error)) QUICVersionProfileProvider {
	var once sync.Once
	supported := CloneQUICVersions(fallbackSupported)
	versionNegotiation := CloneQUICVersions(fallbackVersionNegotiation)
	return func() ([]quic.Version, []quic.Version) {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), quicVersionProbeTimeout)
			defer cancel()
			advertised, err := ProbeQUICVersionNegotiation(ctx, address, dialer)
			if err != nil {
				if onProbeError != nil {
					onProbeError(err)
				}
				return
			}
			normalizedSupported := supportedQUICVersions(advertised)
			if len(normalizedSupported) == 0 {
				if onProbeError != nil {
					onProbeError(errors.New("shadowquic: upstream advertised no supported QUIC versions"))
				}
				return
			}
			supported = normalizedSupported
			versionNegotiation = advertisedQUICVersions(advertised)
		})
		return CloneQUICVersions(supported), CloneQUICVersions(versionNegotiation)
	}
}

func advertisedQUICVersions(versions []quic.Version) []quic.Version {
	advertised := make([]quic.Version, 0, len(versions))
	for _, version := range versions {
		if version == 0 || containsQUICVersion(advertised, version) {
			continue
		}
		advertised = append(advertised, version)
	}
	return advertised
}

func CloneQUICVersions(versions []quic.Version) []quic.Version {
	if len(versions) == 0 {
		return nil
	}
	cloned := make([]quic.Version, len(versions))
	copy(cloned, versions)
	return cloned
}

func ProbeQUICVersionNegotiation(ctx context.Context, address string, dialer quic.JLSPacketDialer) ([]quic.Version, error) {
	if dialer == nil {
		return nil, errors.New("shadowquic: QUIC version probe dialer is nil")
	}
	pc, upstreamAddr, err := dialer(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	defer pc.Close()

	deadline := time.Now().Add(quicVersionProbeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := pc.SetDeadline(deadline); err != nil {
		return nil, err
	}

	probe, err := composeQUICVersionProbe()
	if err != nil {
		return nil, err
	}
	if _, err := pc.WriteTo(probe, upstreamAddr); err != nil {
		return nil, err
	}

	buf := make([]byte, quicVersionProbeSize)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return parseQUICVersionNegotiation(buf[:n])
}

func NormalizeQUICVersionProfile(versions []quic.Version) ([]quic.Version, []quic.Version) {
	supported := supportedQUICVersions(versions)
	if len(supported) == 0 {
		supported = DefaultQUICVersions()
	}
	return supported, CloneQUICVersions(supported)
}

func supportedQUICVersions(versions []quic.Version) []quic.Version {
	var supported []quic.Version
	for _, version := range versions {
		if !isSupportedQUICVersion(version) {
			continue
		}
		if !containsQUICVersion(supported, version) {
			supported = append(supported, version)
		}
	}
	return supported
}

func composeQUICVersionProbe() ([]byte, error) {
	var dcid [8]byte
	var scid [8]byte
	if _, err := io.ReadFull(rand.Reader, dcid[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, scid[:]); err != nil {
		return nil, err
	}

	packet := make([]byte, 0, quicVersionProbeSize)
	packet = append(packet, 0xc3)
	packet = binary.BigEndian.AppendUint32(packet, uint32(quicVersionProbeVersion))
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid[:]...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid[:]...)
	for len(packet) < quicVersionProbeSize {
		packet = append(packet, 0)
	}
	return packet, nil
}

func parseQUICVersionNegotiation(packet []byte) ([]quic.Version, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return nil, errors.New("not a QUIC Version Negotiation packet")
	}
	if binary.BigEndian.Uint32(packet[1:5]) != 0 {
		return nil, errors.New("not a QUIC Version Negotiation packet")
	}

	offset := 5
	if offset >= len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen > len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	offset += dcidLen

	if offset >= len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	scidLen := int(packet[offset])
	offset++
	if offset+scidLen > len(packet) {
		return nil, io.ErrUnexpectedEOF
	}
	offset += scidLen

	if len(packet)-offset < 4 {
		return nil, errors.New("QUIC Version Negotiation packet has no versions")
	}
	versions := make([]quic.Version, 0, (len(packet)-offset)/4)
	for offset+4 <= len(packet) {
		versions = append(versions, quic.Version(binary.BigEndian.Uint32(packet[offset:offset+4])))
		offset += 4
	}
	return versions, nil
}

func ParseQUICVersion(value string) (quic.Version, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	switch normalized {
	case "v1", "1", "rfc9000", "rfc-9000":
		return quic.Version1, nil
	case "v2", "2", "rfc9369", "rfc-9369":
		return quic.Version2, nil
	}
	return 0, fmt.Errorf("unsupported QUIC version %q (supported: v1, v2)", value)
}

func isSupportedQUICVersion(version quic.Version) bool {
	return version == quic.Version1 || version == quic.Version2
}

func containsQUICVersion(versions []quic.Version, version quic.Version) bool {
	for _, v := range versions {
		if v == version {
			return true
		}
	}
	return false
}
