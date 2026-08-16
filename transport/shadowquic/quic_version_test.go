package shadowquic

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go"
)

func TestParseQUICVersionProfile(t *testing.T) {
	supported, versionNegotiation, err := ParseQUICVersionProfile([]string{
		"v1",
		"v2",
		"rfc9000",
		"rfc-9369",
		"v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	wantSupported := []quic.Version{quic.Version1, quic.Version2}
	if !equalQUICVersions(supported, wantSupported) {
		t.Fatalf("supported versions = %v, want %v", supported, wantSupported)
	}

	wantVN := []quic.Version{quic.Version1, quic.Version2}
	if !equalQUICVersions(versionNegotiation, wantVN) {
		t.Fatalf("VN versions = %v, want %v", versionNegotiation, wantVN)
	}
}

func TestParseQUICVersionProfileRejectsUnsupportedVersions(t *testing.T) {
	for _, version := range []string{"draft-29", "0xabcd0000", "v3"} {
		t.Run(version, func(t *testing.T) {
			if _, _, err := ParseQUICVersionProfile([]string{version}); err == nil {
				t.Fatalf("ParseQUICVersionProfile(%q) succeeded", version)
			}
		})
	}
}

func TestNormalizeQUICVersionProfileFallsBackToV1Support(t *testing.T) {
	supported, versionNegotiation := NormalizeQUICVersionProfile([]quic.Version{0xff00001d, 0xabcd0000})
	wantSupported := []quic.Version{quic.Version1}
	if !equalQUICVersions(supported, wantSupported) {
		t.Fatalf("supported versions = %v, want %v", supported, wantSupported)
	}
	wantVN := []quic.Version{quic.Version1}
	if !equalQUICVersions(versionNegotiation, wantVN) {
		t.Fatalf("VN versions = %v, want %v", versionNegotiation, wantVN)
	}
}

func TestResolveQUICVersionProfileUsesConfiguredProfile(t *testing.T) {
	supported, versionNegotiation, provider, err := ResolveQUICVersionProfile(
		[]string{"v2", "v1"},
		"127.0.0.1:443",
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider != nil {
		t.Fatal("static profile should not install a lazy probe")
	}
	if !equalQUICVersions(supported, []quic.Version{quic.Version2, quic.Version1}) {
		t.Fatalf("supported versions = %v", supported)
	}
	if !equalQUICVersions(versionNegotiation, []quic.Version{quic.Version2, quic.Version1}) {
		t.Fatalf("VN versions = %v", versionNegotiation)
	}
}

func TestResolveQUICVersionProfileDefersProbe(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	supported, versionNegotiation, provider, err := ResolveQUICVersionProfile(
		nil,
		upstream.LocalAddr().String(),
		true,
		testJLSPacketDialer(t),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider == nil {
		t.Fatal("probe-enabled upstream did not install a lazy profile")
	}
	if !equalQUICVersions(supported, []quic.Version{quic.Version1}) {
		t.Fatalf("fallback supported versions = %v", supported)
	}
	if !equalQUICVersions(versionNegotiation, DefaultQUICVersionNegotiationVersions()) {
		t.Fatalf("fallback VN versions = %v", versionNegotiation)
	}

	if err := upstream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_, _, err = upstream.ReadFrom(buf)
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("probe ran before the lazy profile was used: %v", err)
	}

	wantVersions := []quic.Version{quic.Version2, 0xff00001d, quic.Version1, 0xabcd0000}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		_, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = upstream.WriteTo(composeVNResponse(wantVersions), addr)
	}()

	gotSupported, gotVN := provider()
	<-done
	if !equalQUICVersions(gotSupported, []quic.Version{quic.Version2, quic.Version1}) {
		t.Fatalf("lazy supported versions = %v", gotSupported)
	}
	wantNormalized := wantVersions
	if !equalQUICVersions(gotVN, wantNormalized) {
		t.Fatalf("lazy VN versions = %v, want %v", gotVN, wantNormalized)
	}
}

func TestLazyQUICVersionProfileKeepsFallbackForUnsupportedProbe(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		_, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = upstream.WriteTo(composeVNResponse([]quic.Version{0xff00001d, 0xabcd0000}), addr)
	}()

	probeErr := make(chan error, 1)
	fallback := []quic.Version{quic.Version2}
	provider := NewLazyQUICVersionProfile(
		upstream.LocalAddr().String(),
		testJLSPacketDialer(t),
		fallback,
		fallback,
		func(err error) { probeErr <- err },
	)
	supported, versionNegotiation := provider()
	<-done
	if !equalQUICVersions(supported, fallback) || !equalQUICVersions(versionNegotiation, fallback) {
		t.Fatalf("profile after unsupported probe: supported=%v VN=%v, want %v", supported, versionNegotiation, fallback)
	}
	select {
	case err := <-probeErr:
		if err == nil {
			t.Fatal("unsupported probe reported a nil error")
		}
	default:
		t.Fatal("unsupported probe did not report an error")
	}
}

func TestProbeQUICVersionNegotiation(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	wantVersions := []quic.Version{quic.Version1, quic.Version2, 0xff00001d}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		_, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = upstream.WriteTo(composeVNResponse(wantVersions), addr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gotVersions, err := ProbeQUICVersionNegotiation(ctx, upstream.LocalAddr().String(), testJLSPacketDialer(t))
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !equalQUICVersions(gotVersions, wantVersions) {
		t.Fatalf("probed versions = %v, want %v", gotVersions, wantVersions)
	}
}

func TestComposeQUICVersionProbeUsesUnsupportedVersion(t *testing.T) {
	probe, err := composeQUICVersionProbe()
	if err != nil {
		t.Fatal(err)
	}
	version := quic.Version(binary.BigEndian.Uint32(probe[1:5]))
	if version == 0 || isSupportedQUICVersion(version) {
		t.Fatalf("probe version = %#x, want a non-zero unsupported version", version)
	}
}

func testJLSPacketDialer(t *testing.T) quic.JLSPacketDialer {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.PacketConn, net.Addr, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		pc, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			_ = pc.Close()
			return nil, nil, err
		}
		return pc, addr, nil
	}
}

func composeVNResponse(versions []quic.Version) []byte {
	response := []byte{0x80, 0, 0, 0, 0, 0, 0}
	for _, version := range versions {
		response = binary.BigEndian.AppendUint32(response, uint32(version))
	}
	return response
}

func equalQUICVersions(a, b []quic.Version) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
