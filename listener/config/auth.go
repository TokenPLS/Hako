package config

import (
	"github.com/TokenPLS/Hako/component/auth"
	"github.com/TokenPLS/Hako/listener/reality"
)

// AuthServer for http/socks/mixed server
type AuthServer struct {
	Enable         bool
	Listen         string
	AuthStore      auth.AuthStore
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	RealityConfig  reality.Config
}
