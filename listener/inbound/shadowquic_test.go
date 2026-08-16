package inbound_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter/outbound"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/listener/inbound"

	"github.com/metacubex/jls-quic-go"
	"github.com/stretchr/testify/assert"
)

func TestInboundShadowQuic(t *testing.T) {
	for _, test := range []struct {
		name          string
		clientVersion string
		serverVersion string
		probedVersion quic.Version
	}{
		{name: "v1", clientVersion: "v1", serverVersion: "v1"},
		{name: "v2", clientVersion: "v2", serverVersion: "v2"},
		{name: "v1 with server probe", clientVersion: "v1", serverVersion: "v2", probedVersion: quic.Version1},
		{name: "v2 with server probe", clientVersion: "v2", serverVersion: "v1", probedVersion: quic.Version2},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testInboundShadowQuic(t, test.clientVersion, test.serverVersion, test.probedVersion)
		})
	}
}

func testInboundShadowQuic(t *testing.T, clientVersion, serverVersion string, probedVersion quic.Version) {
	const username = "shadowquic-user"
	const password = "shadowquic-password"

	inboundOptions := inbound.ShadowQuicOption{
		BaseOption: inbound.BaseOption{
			NameStr: "shadowquic_inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		ALPN:                 []string{"h3"},
		QUICVersions:         []string{serverVersion},
		ZeroRTT:              true,
		MaxIdleTime:          30000,
		MaxDatagramFrameSize: 1400,
		Users:                []inbound.ShadowQuicUser{{Username: username, Password: password}},
		JLSUpstream:          inbound.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"},
	}
	var probeResult <-chan error
	var probeHandler func(C.UDPPacket, *C.Metadata)
	if probedVersion != 0 {
		upstreamAddr, result, handler := newShadowQuicVersionProbeUpstream(probedVersion)
		probeResult = result
		probeHandler = handler
		inboundOptions.JLSUpstream = inbound.ShadowQuicJLSUpstream{
			Addr:             upstreamAddr,
			Proxy:            "shadowquic-probe-proxy",
			QUICVersionProbe: true,
		}
	}
	in, err := inbound.NewShadowQuic(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	if probeHandler != nil {
		tunnel.HandleUDPPacketFn = probeHandler
	} else {
		tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
			packet.Drop()
			t.Errorf("authenticated ShadowQUIC connection unexpectedly accessed JLS upstream %s", metadata.RemoteAddress())
		}
	}

	if !assert.NoError(t, in.Listen(tunnel)) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions := outbound.ShadowQuicOption{
		Name:                 "shadowquic_outbound",
		Server:               addrPort.Addr().String(),
		Port:                 int(addrPort.Port()),
		ALPN:                 []string{"h3"},
		QUICVersions:         []string{clientVersion},
		ZeroRTT:              true,
		MaxDatagramFrameSize: 1400,
		Username:             username,
		Password:             password,
	}
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewShadowQuic(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
	if probeResult != nil {
		select {
		case err := <-probeResult:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for ShadowQUIC version probe")
		}
	}
}

func newShadowQuicVersionProbeUpstream(version quic.Version) (string, <-chan error, func(C.UDPPacket, *C.Metadata)) {
	result := make(chan error, 1)
	handler := func(packet C.UDPPacket, metadata *C.Metadata) {
		defer packet.Drop()
		var probeErr error
		if metadata.Type != C.INNER || metadata.NetWork != C.UDP {
			probeErr = fmt.Errorf("version probe type/network = %s/%s, want Inner/udp", metadata.Type, metadata.NetWork)
		} else if metadata.RemoteAddress() != "127.0.0.1:443" {
			probeErr = fmt.Errorf("version probe destination = %s", metadata.RemoteAddress())
		} else if metadata.SpecialProxy != "shadowquic-probe-proxy" {
			probeErr = fmt.Errorf("version probe proxy = %q", metadata.SpecialProxy)
		}
		response, err := composeShadowQuicVersionNegotiation(packet.Data(), version)
		if err == nil {
			_, err = packet.WriteBack(response, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443})
		}
		if probeErr == nil {
			probeErr = err
		}
		select {
		case result <- probeErr:
		default:
		}
	}
	return "127.0.0.1:443", result, handler
}

func composeShadowQuicVersionNegotiation(probe []byte, version quic.Version) ([]byte, error) {
	if len(probe) < 7 {
		return nil, errors.New("short QUIC version probe")
	}
	if probe[0]&0x80 == 0 {
		return nil, errors.New("QUIC version probe does not use a long header")
	}
	probeVersion := quic.Version(binary.BigEndian.Uint32(probe[1:5]))
	if probeVersion == 0 || probeVersion == quic.Version1 || probeVersion == quic.Version2 {
		return nil, fmt.Errorf("QUIC version probe uses non-probe version %#x", probeVersion)
	}
	offset := 5
	dcidLen := int(probe[offset])
	offset++
	if offset+dcidLen >= len(probe) {
		return nil, errors.New("invalid QUIC version probe destination connection ID")
	}
	dcid := probe[offset : offset+dcidLen]
	offset += dcidLen
	scidLen := int(probe[offset])
	offset++
	if offset+scidLen > len(probe) {
		return nil, errors.New("invalid QUIC version probe source connection ID")
	}
	scid := probe[offset : offset+scidLen]

	response := []byte{0x80, 0, 0, 0, 0, byte(len(scid))}
	response = append(response, scid...)
	response = append(response, byte(len(dcid)))
	response = append(response, dcid...)
	response = binary.BigEndian.AppendUint32(response, uint32(version))
	return response, nil
}
