package statistic

import (
	"os"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/common/xsync"
	"github.com/TokenPLS/Hako/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
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
		pid:                int32(os.Getpid()),
		lastReadAt:         atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections        xsync.Map[string, Tracker]
	uploadTemp         atomic.Int64
	downloadTemp       atomic.Int64
	uploadBlip         atomic.Int64
	downloadBlip       atomic.Int64
	uploadTotal        atomic.Int64
	downloadTotal      atomic.Int64
	proxyUploadTemp    atomic.Int64
	proxyDownloadTemp  atomic.Int64
	proxyUploadBlip    atomic.Int64
	proxyDownloadBlip  atomic.Int64
	proxyUploadTotal   atomic.Int64
	proxyDownloadTotal atomic.Int64
	// Session-long buckets the widget reads; the proxy bucket is the pair above.
	directUploadTotal   atomic.Int64
	directDownloadTotal atomic.Int64
	rejectUploadTotal   atomic.Int64
	rejectDownloadTotal atomic.Int64
	opened              atomic.Int64
	active              atomic.Int64
	rejected            atomic.Int64
	pid                 int32
	memory              uint64

	// lastReadAt is when a caller last asked for a rate, as Unix nanoseconds. The sampler
	// stops when nobody has asked recently and the next read wakes it. See handle().
	lastReadAt atomic.Int64
	sampleWake chan struct{}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	if _, present := m.connections.LoadAndDelete(c.ID()); present {
		m.noteLeave()
	}
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

// reservedNonProxyOutbounds are the built-in egress names (adapter/outbound)
// whose bytes are not real proxy traffic and must be excluded from the
// proxy-only counters used as release evidence: the direct/reject/
// pass/compatible pseudo-outbounds. finalOutbound is the real egress name
// (Chain.Last()). A user-named direct-type outbound is not covered here — the
// egress adapter's type is not reachable from this package without an import
// cycle, so type-exact classification would have to be threaded from the dial
// site.
// OutboundBucket is where a connection's bytes are counted by the outbound it finally
// left through: a real proxy, the device's own network, or nowhere. It is decided once,
// when the tracker is built, from the outbound's name -- the reserved names are the
// built-in egresses, everything else is a proxy -- which is the same line the proxy-only
// counters have drawn since, so a widget reading the proxy bucket reads the
// figure the release evidence reads. A user-defined outbound of type direct with a name
// of its own counts as a proxy here, exactly as it does there.
type OutboundBucket uint8

const (
	BucketProxy OutboundBucket = iota
	BucketDirect
	BucketReject
)

var reservedOutboundBuckets = map[string]OutboundBucket{
	"DIRECT":      BucketDirect,
	"COMPATIBLE":  BucketDirect,
	"PASS":        BucketDirect,
	"REJECT":      BucketReject,
	"REJECT-DROP": BucketReject,
}

// BucketForOutbound names the bucket a final outbound's bytes and connection belong to.
func BucketForOutbound(finalOutbound string) OutboundBucket {
	if bucket, reserved := reservedOutboundBuckets[finalOutbound]; reserved {
		return bucket
	}
	return BucketProxy
}

func isProxyOutbound(finalOutbound string) bool {
	return BucketForOutbound(finalOutbound) == BucketProxy
}

// PushUploaded counts bytes by outbound name. Trackers decide the bucket once and call
// pushUploaded; this entry point stays for callers that only hold a name.
func (m *Manager) PushUploaded(finalOutbound string, size int64) {
	m.pushUploaded(BucketForOutbound(finalOutbound), size)
}

func (m *Manager) PushDownloaded(finalOutbound string, size int64) {
	m.pushDownloaded(BucketForOutbound(finalOutbound), size)
}

func (m *Manager) pushUploaded(bucket OutboundBucket, size int64) {
	switch bucket {
	case BucketProxy:
		m.proxyUploadTemp.Add(size)
		m.proxyUploadTotal.Add(size)
	case BucketDirect:
		m.directUploadTotal.Add(size)
	case BucketReject:
		m.rejectUploadTotal.Add(size)
	}
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) pushDownloaded(bucket OutboundBucket, size int64) {
	switch bucket {
	case BucketProxy:
		m.proxyDownloadTemp.Add(size)
		m.proxyDownloadTotal.Add(size)
	case BucketDirect:
		m.directDownloadTotal.Add(size)
	case BucketReject:
		m.rejectDownloadTotal.Add(size)
	}
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

// BucketTotal is one bucket's session-long byte totals.
type BucketTotal struct {
	Up   int64
	Down int64
}

// OutboundTotals is what the widget asks for: bytes per bucket and connection counts,
// all since this process started. Active is the number of tracked connections open
// right now; Rejected counts connections handed to a reject outbound.
type OutboundTotals struct {
	Proxy    BucketTotal
	Direct   BucketTotal
	Reject   BucketTotal
	Opened   int64
	Active   int64
	Rejected int64
}

func (m *Manager) OutboundTotals() OutboundTotals {
	return OutboundTotals{
		Proxy:    BucketTotal{Up: m.proxyUploadTotal.Load(), Down: m.proxyDownloadTotal.Load()},
		Direct:   BucketTotal{Up: m.directUploadTotal.Load(), Down: m.directDownloadTotal.Load()},
		Reject:   BucketTotal{Up: m.rejectUploadTotal.Load(), Down: m.rejectDownloadTotal.Load()},
		Opened:   m.opened.Load(),
		Active:   m.active.Load(),
		Rejected: m.rejected.Load(),
	}
}

// noteJoin and noteLeave keep the connection counts beside the byte counters, on the
// open/close path rather than the byte path.
func (m *Manager) noteJoin(bucket OutboundBucket) {
	m.opened.Add(1)
	m.active.Add(1)
	if bucket == BucketReject {
		m.rejected.Add(1)
	}
}

func (m *Manager) noteLeave() {
	m.active.Add(-1)
}

// Now returns the transfer rate over the last sampled second.
//
// Reading it is what keeps the sampler running: it stops when nobody has asked for
// sampleIdleTimeout, so a caller that wants rates has to ask for them. Snapshot deliberately does
// NOT mark a read -- it returns totals and connections, not rates, so waking the sampler for it
// would put the ticker back for callers that never look at a rate.
func (m *Manager) Now() (up int64, down int64) {
	m.noteRateRead()
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) NowTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		m.noteRateRead()
		return m.proxyUploadBlip.Load(), m.proxyDownloadBlip.Load()
	}
	return m.Now()
}

func (m *Manager) TotalTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		return m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()
	}
	return m.Total()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
	m.proxyUploadTemp.Store(0)
	m.proxyUploadBlip.Store(0)
	m.proxyUploadTotal.Store(0)
	m.proxyDownloadTemp.Store(0)
	m.proxyDownloadBlip.Store(0)
	m.proxyDownloadTotal.Store(0)
}

// sampleIdleTimeout is how long the sampler keeps running after the last time anyone asked for
// a rate. It only has to outlast a once-per-second poller comfortably; sing-box's equivalent
// stops the instant its HTTP client disconnects, and "nobody has asked for five seconds" is the
// closest thing to a disconnect an on-demand API has.
const sampleIdleTimeout = 5 * time.Second

// handle samples the per-second transfer rate, and only while someone is reading it.
//
// This used to be an unconditional 1 Hz ticker started at package init and never stopped: it ran
// for the life of every process that imported this package, with no reader and no tunnel
// required. sing-box has no process-lifetime accounting ticker at all -- its equivalents live
// inside the clash-api HTTP handlers with defer tick.Stop(), so they exist only while a client is
// attached (experimental/clashapi/server.go, api_meta.go).
//
// Our readers are one-shot calls rather than long-lived subscriptions, so "while a client is
// attached" becomes "while someone has asked recently".
//
// The subtle part is RESUMING. The temp counters keep accumulating while the sampler is stopped,
// so publishing that accumulation as a one-second rate would display a spike that never happened
// -- a whole idle span reported as one second of traffic. On resume the accumulation is therefore
// DISCARDED, and the first published rate covers a real second of sampling.
func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		if m.sampleIdle() {
			ticker.Stop()
			<-m.sampleWake
			// Throw away everything that accumulated while nothing was sampling. Publishing it
			// would be a rate spike for a second that never carried that traffic.
			m.uploadTemp.Store(0)
			m.downloadTemp.Store(0)
			m.proxyUploadTemp.Store(0)
			m.proxyDownloadTemp.Store(0)
			ticker.Reset(time.Second)
			continue
		}

		select {
		case <-ticker.C:
		case <-m.sampleWake:
			// A read arrived; keep sampling on the existing cadence.
			continue
		}

		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
		m.proxyUploadBlip.Store(m.proxyUploadTemp.Swap(0))
		m.proxyDownloadBlip.Store(m.proxyDownloadTemp.Swap(0))
	}
}

// sampleIdle reports whether nobody has asked for a rate recently.
func (m *Manager) sampleIdle() bool {
	last := m.lastReadAt.Load()
	if last == 0 {
		// Nobody has ever read a rate in this process. Common in the Network Extension, where
		// the containing App may never open a traffic view.
		return true
	}
	return time.Since(time.Unix(0, last)) > sampleIdleTimeout
}

// noteRateRead records that someone wants rates and wakes the sampler if it stopped.
func (m *Manager) noteRateRead() {
	m.lastReadAt.Store(time.Now().UnixNano())
	select {
	case m.sampleWake <- struct{}{}:
	default:
		// A wake is already pending, or the sampler is running and will see lastReadAt.
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
