//go:build !with_quic

package networkquality

import (
	"errors"

	N "github.com/metacubex/sing/common/network"
)

func HTTP3Available() bool { return false }

func NewHTTP3MeasurementClientFactory(dialer N.Dialer) (MeasurementClientFactory, error) {
	return nil, errors.New("hako: HTTP/3 network quality support is not included")
}
