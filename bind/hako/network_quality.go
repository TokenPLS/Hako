package hako

import (
	"context"
	"time"

	"github.com/TokenPLS/Hako/bind/hako/internal/networkquality"
)

const NetworkQualityDefaultConfigURL = networkquality.DefaultConfigURL
const NetworkQualityDefaultMaxRuntimeSeconds = int32(networkquality.DefaultMaxRuntime / time.Second)

// NetworkQualityHTTP3Available reports the compile-time SDK capability. It
// does not probe the current network or initialize a QUIC transport.
func NetworkQualityHTTP3Available() bool {
	return networkquality.HTTP3Available()
}

const (
	NetworkQualityAccuracyLow    = int32(networkquality.AccuracyLow)
	NetworkQualityAccuracyMedium = int32(networkquality.AccuracyMedium)
	NetworkQualityAccuracyHigh   = int32(networkquality.AccuracyHigh)
)

const (
	NetworkQualityPhaseIdle     = int32(networkquality.PhaseIdle)
	NetworkQualityPhaseDownload = int32(networkquality.PhaseDownload)
	NetworkQualityPhaseUpload   = int32(networkquality.PhaseUpload)
	NetworkQualityPhaseDone     = int32(networkquality.PhaseDone)
)

type NetworkQualityProgress struct {
	Phase                    int32
	DownloadCapacity         int64
	UploadCapacity           int64
	DownloadRPM              int32
	UploadRPM                int32
	IdleLatencyMs            int32
	ElapsedMs                int64
	DownloadCapacityAccuracy int32
	UploadCapacityAccuracy   int32
	DownloadRPMAccuracy      int32
	UploadRPMAccuracy        int32
}

type NetworkQualityResult struct {
	DownloadCapacity         int64
	UploadCapacity           int64
	DownloadRPM              int32
	UploadRPM                int32
	IdleLatencyMs            int32
	DownloadCapacityAccuracy int32
	UploadCapacityAccuracy   int32
	DownloadRPMAccuracy      int32
	UploadRPMAccuracy        int32
}

type NetworkQualityTestHandler interface {
	OnProgress(progress *NetworkQualityProgress)
	OnResult(result *NetworkQualityResult)
	OnError(message string)
}

// NetworkQualityTest mirrors libbox's standalone test. When created in the
// container app while the packet tunnel is connected, its sockets traverse
// the active VPN and are independently observed by mihomo /traffic.
type NetworkQualityTest struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewNetworkQualityTest() *NetworkQualityTest {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkQualityTest{ctx: ctx, cancel: cancel}
}

func (t *NetworkQualityTest) Start(configURL string, serial bool, maxRuntimeSeconds int32, http3 bool, handler NetworkQualityTestHandler) {
	if handler == nil {
		return
	}
	go func() {
		httpClient := networkquality.NewHTTPClient(nil)
		defer httpClient.CloseIdleConnections()

		measurementClientFactory, err := networkquality.NewOptionalHTTP3Factory(nil, http3)
		if err != nil {
			handler.OnError(err.Error())
			return
		}

		result, err := networkquality.Run(networkquality.Options{
			ConfigURL:            configURL,
			HTTPClient:           httpClient,
			NewMeasurementClient: measurementClientFactory,
			Serial:               serial,
			MaxRuntime:           time.Duration(maxRuntimeSeconds) * time.Second,
			Context:              t.ctx,
			OnProgress: func(progress networkquality.Progress) {
				handler.OnProgress(networkQualityProgress(progress))
			},
		})
		if err != nil {
			handler.OnError(err.Error())
			return
		}
		handler.OnResult(&NetworkQualityResult{
			DownloadCapacity:         result.DownloadCapacity,
			UploadCapacity:           result.UploadCapacity,
			DownloadRPM:              result.DownloadRPM,
			UploadRPM:                result.UploadRPM,
			IdleLatencyMs:            result.IdleLatencyMs,
			DownloadCapacityAccuracy: int32(result.DownloadCapacityAccuracy),
			UploadCapacityAccuracy:   int32(result.UploadCapacityAccuracy),
			DownloadRPMAccuracy:      int32(result.DownloadRPMAccuracy),
			UploadRPMAccuracy:        int32(result.UploadRPMAccuracy),
		})
	}()
}

func (t *NetworkQualityTest) Cancel() {
	if t != nil && t.cancel != nil {
		t.cancel()
	}
}

func FormatBitrate(bitsPerSecond int64) string {
	return networkquality.FormatBitrate(bitsPerSecond)
}

func networkQualityProgress(progress networkquality.Progress) *NetworkQualityProgress {
	return &NetworkQualityProgress{
		Phase:                    int32(progress.Phase),
		DownloadCapacity:         progress.DownloadCapacity,
		UploadCapacity:           progress.UploadCapacity,
		DownloadRPM:              progress.DownloadRPM,
		UploadRPM:                progress.UploadRPM,
		IdleLatencyMs:            progress.IdleLatencyMs,
		ElapsedMs:                progress.ElapsedMs,
		DownloadCapacityAccuracy: int32(progress.DownloadCapacityAccuracy),
		UploadCapacityAccuracy:   int32(progress.UploadCapacityAccuracy),
		DownloadRPMAccuracy:      int32(progress.DownloadRPMAccuracy),
		UploadRPMAccuracy:        int32(progress.UploadRPMAccuracy),
	}
}
