package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	F "github.com/metacubex/sing/common/format"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/ranges"
)

type Handler interface {
	PrepareConnection(
		network string,
		source M.Socksaddr,
		destination M.Socksaddr,
		routeContext DirectRouteContext,
		timeout time.Duration,
	) (DirectRouteDestination, error)
	N.TCPConnectionHandler
	PacketHandler
	E.Handler
}

type DirectRouteContext interface {
	WritePacket(packet []byte) error
}

type PacketHandler interface {
	NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter)
}

type Tun interface {
	io.ReadWriter
	Close() error
}

type WinTun interface {
	Tun
	ReadPacket() ([]byte, func(), error)
}

type LinuxTUN interface {
	Tun
	N.FrontHeadroom
	BatchSize() int
	BatchRead(buffers [][]byte, offset int, readN []int) (n int, err error)
	BatchWrite(buffers [][]byte, offset int) (n int, err error)
	TXChecksumOffload() bool
}

type DarwinTUN interface {
	Tun
	BatchRead() ([]*buf.Buffer, error)
	BatchWrite(buffers []*buf.Buffer) error
}

const (
	DefaultIPRoute2TableIndex                    = 2022
	DefaultIPRoute2RuleIndex                     = 9000
	DefaultIPRoute2AutoRedirectFallbackRuleIndex = 32768
)

type Options struct {
	Name                                  string
	Inet4Address                          []netip.Prefix
	Inet6Address                          []netip.Prefix
	MTU                                   uint32
	GSO                                   bool
	AutoRoute                             bool
	Inet4Gateway                          netip.Addr
	Inet6Gateway                          netip.Addr
	DNSServers                            []netip.Addr
	IPRoute2TableIndex                    int
	IPRoute2RuleIndex                     int
	IPRoute2AutoRedirectFallbackRuleIndex int
	AutoRedirectMarkMode                  bool
	AutoRedirectInputMark                 uint32
	AutoRedirectOutputMark                uint32
	ExcludeMPTCP                          bool
	Inet4LoopbackAddress                  []netip.Addr
	Inet6LoopbackAddress                  []netip.Addr
	StrictRoute                           bool
	Inet4RouteAddress                     []netip.Prefix
	Inet6RouteAddress                     []netip.Prefix
	Inet4RouteExcludeAddress              []netip.Prefix
	Inet6RouteExcludeAddress              []netip.Prefix
	IncludeInterface                      []string
	ExcludeInterface                      []string
	IncludeUID                            []ranges.Range[uint32]
	ExcludeUID                            []ranges.Range[uint32]
	ExcludeSrcPort                        []ranges.Range[uint16]
	ExcludeDstPort                        []ranges.Range[uint16]
	IncludeAndroidUser                    []int
	IncludePackage                        []string
	ExcludePackage                        []string
	IncludeMACAddress                     []net.HardwareAddr
	ExcludeMACAddress                     []net.HardwareAddr
	InterfaceMonitor                      DefaultInterfaceMonitor
	FileDescriptor                        int
	Logger                                logger.Logger

	// No work for TCP, do not use.
	_TXChecksumOffload bool

	// For library usages.
	EXP_DisableDNSHijack bool

	// For darwin tun
	EXP_RecvMsgX bool
	EXP_SendMsgX bool
}

func (o *Options) Inet4GatewayAddr() netip.Addr {
	if o.Inet4Gateway.IsValid() {
		return o.Inet4Gateway
	}
	if len(o.Inet4Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet4Address[0], 1) {
				return o.Inet4Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet4Address[0].Addr()
		default:
			if HasNextAddress(o.Inet4Address[0], 1) {
				return o.Inet4Address[0].Addr().Next()
			} else {
				return o.Inet4Address[0].Addr()
			}
		}
	}
	return netip.IPv4Unspecified()
}

func (o *Options) Inet6GatewayAddr() netip.Addr {
	if o.Inet6Gateway.IsValid() {
		return o.Inet6Gateway
	}
	if len(o.Inet6Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet6Address[0], 1) {
				return o.Inet6Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet6Address[0].Addr()
		default:
			if HasNextAddress(o.Inet6Address[0], 1) {
				return o.Inet6Address[0].Addr().Next()
			} else {
				return o.Inet6Address[0].Addr()
			}
		}
	}
	return netip.IPv6Unspecified()
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil && int(index) >= tunIndex {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}
