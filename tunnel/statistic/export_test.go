package statistic

import "github.com/TokenPLS/Hako/common/atomic"

// NewManagerForTest builds a Manager with its counters wired, without the sampler
// goroutine the package-level DefaultManager starts. Tests in other packages use it to
// count into a manager of their own instead of the process-wide one.
func NewManagerForTest() *Manager {
	return &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		proxyUploadTemp:    atomic.NewInt64(0),
		proxyDownloadTemp:  atomic.NewInt64(0),
		proxyUploadBlip:    atomic.NewInt64(0),
		proxyDownloadBlip:  atomic.NewInt64(0),
		proxyUploadTotal:   atomic.NewInt64(0),
		proxyDownloadTotal: atomic.NewInt64(0),
		lastReadAt:         atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}
}
