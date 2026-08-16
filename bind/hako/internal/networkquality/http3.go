//go:build with_quic

// Adapted from sing-box common/networkquality at
// 4bccd6fae19526425acf76efc263333c7aea6fce (GPL-3.0-or-later).
package networkquality

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"fmt"
	"net"
	stdHTTP "net/http"
	stdTrace "net/http/httptrace"

	metaHTTP "github.com/metacubex/http"
	metaTrace "github.com/metacubex/http/httptrace"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	sBufio "github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	metaTLS "github.com/metacubex/tls"
)

func HTTP3Available() bool { return true }

func NewHTTP3MeasurementClientFactory(dialer N.Dialer) (MeasurementClientFactory, error) {
	return newHTTP3MeasurementClientFactory(dialer, nil)
}

func newHTTP3MeasurementClientFactory(dialer N.Dialer, tlsConfig *metaTLS.Config) (MeasurementClientFactory, error) {
	// HTTP/3 multiplexes streams over one QUIC connection. The HTTP/1.1-only
	// singleConnection and disableKeepAlives knobs therefore do not apply.
	return func(connectEndpoint string, _, _ bool, readCounters, writeCounters []N.CountFunc) (*stdHTTP.Client, error) {
		transport := &http3.Transport{
			TLSClientConfig:        cloneTLSConfig(tlsConfig),
			DisableCompression:     true,
			MaxResponseHeaderBytes: 1 << 20,
			Dial: func(ctx context.Context, addr string, tlsConfig *metaTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				dialAddress := addr
				if connectEndpoint != "" {
					dialAddress = rewriteDialAddress(addr, connectEndpoint)
				}
				destination := M.ParseSocksaddr(dialAddress)
				trace := stdTrace.ContextClientTrace(ctx)
				if trace != nil && trace.ConnectStart != nil {
					trace.ConnectStart(N.NetworkUDP, dialAddress)
				}
				var udpConnection net.Conn
				var err error
				if dialer != nil {
					udpConnection, err = dialer.DialContext(ctx, N.NetworkUDP, destination)
				} else {
					var netDialer net.Dialer
					udpConnection, err = netDialer.DialContext(ctx, N.NetworkUDP, destination.String())
				}
				if trace != nil && trace.ConnectDone != nil {
					trace.ConnectDone(N.NetworkUDP, dialAddress, err)
				}
				if err != nil {
					return nil, err
				}

				countedConnection := udpConnection
				if len(readCounters) > 0 || len(writeCounters) > 0 {
					countedConnection = sBufio.NewCounterConn(udpConnection, readCounters, writeCounters)
				}
				packetConnection := sBufio.NewUnbindPacketConn(countedConnection)
				if trace != nil && trace.TLSHandshakeStart != nil {
					trace.TLSHandshakeStart()
				}
				connection, err := quic.DialEarly(ctx, packetConnection, udpConnection.RemoteAddr(), tlsConfig, quicConfig)
				if trace != nil && trace.TLSHandshakeDone != nil {
					trace.TLSHandshakeDone(stdTLS.ConnectionState{Version: stdTLS.VersionTLS13}, err)
				}
				if err != nil {
					_ = udpConnection.Close()
					return nil, err
				}
				return connection, nil
			},
		}
		return &stdHTTP.Client{Transport: &standardHTTP3RoundTripper{transport: transport}}, nil
	}, nil
}

// mihomo's pinned quic-go intentionally uses metacubex/http and
// metacubex/tls. This adapter keeps the copied libbox measurement algorithm on
// net/http while reusing mihomo's one QUIC stack instead of adding a second.
type standardHTTP3RoundTripper struct {
	transport *http3.Transport
}

func (t *standardHTTP3RoundTripper) RoundTrip(request *stdHTTP.Request) (*stdHTTP.Response, error) {
	metaRequest, err := metaHTTP.NewRequestWithContext(
		bridgeHTTPTrace(request.Context()),
		request.Method,
		request.URL.String(),
		request.Body,
	)
	if err != nil {
		return nil, err
	}
	metaRequest.Header = toMetaHeader(request.Header)
	metaRequest.Trailer = toMetaHeader(request.Trailer)
	metaRequest.Host = request.Host
	metaRequest.Close = request.Close
	metaRequest.ContentLength = request.ContentLength
	metaRequest.TransferEncoding = append([]string(nil), request.TransferEncoding...)

	response, err := t.transport.RoundTrip(metaRequest)
	if err != nil {
		if contextError := request.Context().Err(); contextError != nil {
			if errors.Is(contextError, context.Canceled) {
				return nil, contextError
			}
			return nil, fmt.Errorf("hako: HTTP/3 network quality unavailable: %w", contextError)
		}
		return nil, fmt.Errorf("hako: HTTP/3 network quality unavailable: %w", err)
	}
	return &stdHTTP.Response{
		Status:           response.Status,
		StatusCode:       response.StatusCode,
		Proto:            response.Proto,
		ProtoMajor:       response.ProtoMajor,
		ProtoMinor:       response.ProtoMinor,
		Header:           toStandardHeader(response.Header),
		Body:             response.Body,
		ContentLength:    response.ContentLength,
		TransferEncoding: append([]string(nil), response.TransferEncoding...),
		Close:            response.Close,
		Uncompressed:     response.Uncompressed,
		Trailer:          toStandardHeader(response.Trailer),
		Request:          request,
	}, nil
}

func (t *standardHTTP3RoundTripper) Close() error {
	return t.transport.Close()
}

func (t *standardHTTP3RoundTripper) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func bridgeHTTPTrace(ctx context.Context) context.Context {
	trace := stdTrace.ContextClientTrace(ctx)
	if trace == nil {
		return ctx
	}
	bridged := &metaTrace.ClientTrace{}
	if trace.GotConn != nil {
		bridged.GotConn = func(info metaTrace.GotConnInfo) {
			trace.GotConn(stdTrace.GotConnInfo{
				Conn:     info.Conn,
				Reused:   info.Reused,
				WasIdle:  info.WasIdle,
				IdleTime: info.IdleTime,
			})
		}
	}
	if trace.WroteRequest != nil {
		bridged.WroteRequest = func(info metaTrace.WroteRequestInfo) {
			trace.WroteRequest(stdTrace.WroteRequestInfo{Err: info.Err})
		}
	}
	if trace.GotFirstResponseByte != nil {
		bridged.GotFirstResponseByte = trace.GotFirstResponseByte
	}
	return metaTrace.WithClientTrace(ctx, bridged)
}

func toMetaHeader(header stdHTTP.Header) metaHTTP.Header {
	converted := make(metaHTTP.Header, len(header))
	for key, values := range header {
		converted[key] = append([]string(nil), values...)
	}
	return converted
}

func toStandardHeader(header metaHTTP.Header) stdHTTP.Header {
	converted := make(stdHTTP.Header, len(header))
	for key, values := range header {
		converted[key] = append([]string(nil), values...)
	}
	return converted
}

func cloneTLSConfig(config *metaTLS.Config) *metaTLS.Config {
	if config == nil {
		return nil
	}
	return config.Clone()
}
