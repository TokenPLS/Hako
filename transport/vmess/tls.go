package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/TokenPLS/Hako/component/ca"
	"github.com/TokenPLS/Hako/component/ech"
	tlsC "github.com/TokenPLS/Hako/component/tls"
	"github.com/TokenPLS/Hako/transport/jls"
	"github.com/TokenPLS/Hako/transport/restls"
	"github.com/TokenPLS/Hako/transport/shadowtls"
	"github.com/TokenPLS/Hako/transport/tlsmirror"

	"github.com/metacubex/tls"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	NameCertVerify    string
	FingerPrint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	NextProtos        []string
	ECH               *ech.Config
	ShadowTLS         *shadowtls.Config
	Restls            *restls.Config
	JLS               *jls.Config
	Reality           *tlsC.RealityConfig
	TLSMirror         *tlsmirror.Config
	TLSMirrorDialer   tlsmirror.EnrollmentDialer
}

func (cfg *TLSConfig) ToStdConfig() (*tls.Config, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
		},
		Fingerprint:    cfg.FingerPrint,
		NameCertVerify: cfg.NameCertVerify,
		Certificate:    cfg.Certificate,
		PrivateKey:     cfg.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	// No session cache here on purpose. ToStdConfig is NOT TCP-only: TrustTunnel's QUIC
	// round-tripper and the VLESS XHTTP/3 path both build their quic-go TLS config from
	// it, and quic-go manages its own session tickets -- the same reason forbids
	// arming one inside ca.GetTLSConfig. The cache is attached in StreamTLSConn, on the
	// one branch that actually performs a TCP TLS handshake with this config.
	return tlsConfig, nil
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	if cfg.ShadowTLS != nil {
		alpn := cfg.NextProtos
		if alpn == nil {
			alpn = shadowtls.DefaultALPN
		}
		return shadowtls.NewShadowTLS(ctx, conn, &shadowtls.ShadowTLSOption{
			Password:          cfg.ShadowTLS.Password,
			Host:              cfg.Host,
			Fingerprint:       cfg.FingerPrint,
			Certificate:       cfg.Certificate,
			PrivateKey:        cfg.PrivateKey,
			ClientFingerprint: cfg.ClientFingerprint,
			SkipCertVerify:    cfg.SkipCertVerify,
			NameCertVerify:    cfg.NameCertVerify,
			Version:           cfg.ShadowTLS.Version,
			ALPN:              alpn,
		})
	}
	if cfg.Restls != nil {
		restlsConfig := cfg.Restls.Clone()
		restlsConfig.ServerName = cfg.Host
		restlsConfig.NextProtos = cfg.NextProtos
		restlsConfig.InsecureSkipVerify = cfg.SkipCertVerify
		if cfg.FingerPrint != "" {
			if err := restls.SetFingerprint(restlsConfig, cfg.FingerPrint, cfg.NameCertVerify); err != nil {
				return nil, err
			}
		} else if cfg.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, cfg.NameCertVerify)
		}
		return restls.NewRestls(ctx, conn, restlsConfig)
	}
	if cfg.JLS != nil {
		return jls.NewClient(ctx, conn, &jls.ClientConfig{
			Config:            *cfg.JLS,
			ServerName:        cfg.Host,
			ALPN:              cfg.NextProtos,
			ClientFingerprint: cfg.ClientFingerprint,
		})
	}
	if cfg.TLSMirror != nil {
		return tlsmirror.Dial(ctx, conn, tlsmirror.ClientConfig{
			Config:             *cfg.TLSMirror,
			ServerName:         cfg.Host,
			SkipCertVerify:     cfg.SkipCertVerify,
			NameCertVerify:     cfg.NameCertVerify,
			ALPN:               cfg.NextProtos,
			Fingerprint:        cfg.FingerPrint,
			Certificate:        cfg.Certificate,
			PrivateKey:         cfg.PrivateKey,
			ClientFingerprint:  cfg.ClientFingerprint,
			ForwardAddressHint: cfg.Host,
			ECH:                cfg.ECH,
			EnrollmentDialer:   cfg.TLSMirrorDialer,
		})
	}

	tlsConfig, err := cfg.ToStdConfig()
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConfig := tlsC.UConfig(tlsConfig)
		err = cfg.ECH.ClientHandleUTLS(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	err = cfg.ECH.ClientHandle(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	// This is the only branch that hands a metacubex/tls config to a TCP handshake, so it
	// is the only place a ClientSessionCache belongs. Everything above either returned
	// already (shadow-tls, restls, jls, tlsmirror) or converts to uTLS, whose UConfig does
	// not carry ClientSessionCache across -- so arming it earlier reached QUIC callers that
	// must not have it while doing nothing for the paths it appeared to cover.
	//
	// Attached after ECH.ClientHandle so it cannot be overwritten by that step.
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = sessionCacheFor(cfg)
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
