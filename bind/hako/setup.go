package hako

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// embed the tz database — inside the NE sandbox Go cannot
	// resolve the device zone from the filesystem (measured: time.Local
	// silently falls back to UTC). Costs ~450KB, buys correct LoadLocation
	// everywhere.
	_ "time/tzdata"

	"github.com/TokenPLS/Hako/component/ca"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
	C "github.com/TokenPLS/Hako/constant"
	tun "github.com/metacubex/sing-tun"
	"github.com/sirupsen/logrus"
)

// SetupOptions carries process-wide wiring done once before NewService
// (mirrors libbox setup.go SetupOptions, flattened to gomobile-safe fields).
//
// BasePath: App Group root (the short binding-owned Clash API socket lives
// here; other read-only inputs may also be resolved relative to it).
// WorkingPath: App Group working dir — becomes mihomo HomeDir (cache.db,
// providers/, geodata/ live here). TempPath: scratch dir. TimeZone: IANA id
// from Swift (TimeZone.current.identifier) for the tz shim; empty =
// leave Go defaults alone. RuntimeProfile: Apple execution environment;
// empty preserves the historical iOS Packet Tunnel policy. MemoryLimit: NE
// budget in bytes; the Go soft
// limit is set to 3/4 of it (0 = leave runtime default). LogMaxLines:
// retained-log cap for the RecentLogsJSON ring (default 400 when non-positive).
// TunMTU: startup-only Apple/Core link MTU; 0 selects the tested default.
// It is deliberately not sourced from YAML and cannot be changed live.
type SetupOptions struct {
	BasePath    string
	WorkingPath string
	TempPath    string
	TimeZone    string
	// RuntimeProfile selects the Apple execution environment. Empty preserves
	// the historical iosPacketTunnel behavior. The value is startup-only and
	// cannot change while a Core is active.
	RuntimeProfile string
	LogMaxLines    int
	MemoryLimit    int64
	TunMTU         int
	// StartupPhaseLogPath, when set, gets one appended line per stage of
	// Start with the phys_footprint at that moment. Empty disables it.
	StartupPhaseLogPath string
	// DisablePersistentCache must be true only in a containing-App process
	// which calls CheckConfig but never starts a Core. It prevents dry-run
	// parsing from opening the Packet Tunnel's shared cache.db. Extension/Core
	// Setup leaves it false.
	DisablePersistentCache bool
	// MaxProcs caps runtime.GOMAXPROCS to save OS thread stacks under the NE
	// budget. 0 = auto (cap at 4 when MemoryLimit is set,
	// otherwise leave the Go default). Downstream can tune per device.
	MaxProcs int
	// CertificateStore selects where TLS trust anchors come from, mirroring
	// sing-box's certificate.store: "system" (default), "mozilla", "chrome" or
	// "none". Empty means no selection and preserves existing behaviour exactly.
	//
	// It is a process option rather than a configuration field because mihomo keeps
	// ONE certificate pool for the whole process and hands it to every TLS client, so
	// a per-profile field would promise something the mechanism cannot deliver.
	//
	// On Apple this is the only supported way to stop paying an XPC round trip to
	// trustd on every certificate verification: crypto/x509 delegates to the platform
	// whenever the pool carries the systemPool mark, and only "mozilla", "chrome" and
	// "none" produce a pool without it. The cost of selecting one is that every root
	// the platform trusts and the bundle does not is gone, including MDM-installed
	// enterprise roots -- which is why it is a deliberate selection and not a default.
	//
	// Startup-only, like RuntimeProfile: the pool is built lazily and taken by the
	// first TLS client, so a later change would apply to nothing.
	CertificateStore string
	// MemoryPressureShed lets the memory threshold machine close tracked connections when it
	// decides memory is critical. Default false = report only.
	//
	// Upstream acts by default (sing-box's killerDisabled is opt-in the other way). This one is
	// inverted on purpose: the action closes every tracked connection, and an earlier version of
	// this tree shed on every OS notification with the measured result that it freed almost
	// nothing while killing every app's live session. Report-only makes the first device run
	// produce the trigger counts that justify enabling it, instead of making users the
	// experiment. See memoryThreshold* in the diagnostics for those counts.
	MemoryPressureShed bool
}

var (
	setupMu                    sync.Mutex
	setupDone                  bool
	setupCacheDisabled         bool
	setupStartupPhaseLogPath   string
	setupClashAPIPath          string
	setupOOMEvidencePath       string
	setupGoCrashReportBasePath string
	timeZoneMu                 sync.Mutex
	configuredTimeZone         string
	configuredLocation         atomic.Pointer[time.Location]

	tracebackOnce sync.Once
)

// gVisorTCPBufferOverrideFile is an optional App-Group file an out-of-band benchmark tool writes to tune the gVisor TCP window (tun.GVisorTCPBufferBytes)
// without shipping a knob in the public SetupOptions API — it is startup-only and
// not YAML-sourced, like TunMTU. Absent in production, so the historical 20 KiB
// default holds.
const gVisorTCPBufferOverrideFile = "hako-gvisor-tcp-buffer-bytes"

// applyGVisorTCPBufferOverride widens (or narrows) the gVisor TCP window before
// any Core starts. A missing file, an unreadable file, or a non-positive value
// leaves the default untouched, so it is a no-op in production.
func applyGVisorTCPBufferOverride(basePath string) {
	data, err := os.ReadFile(filepath.Join(basePath, gVisorTCPBufferOverrideFile))
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n <= 0 {
		return
	}
	tun.GVisorTCPBufferBytes = n
	logrus.Warnf("[iOS] gVisor TCP window overridden to %d bytes via %s (benchmark knob)", n, gVisorTCPBufferOverrideFile)
}

// Setup performs process-wide initialization and must succeed before
// NewService. Calling it again re-wires test paths, but Hako's presentation
// timezone is startup-only; the process-global time.Local is never mutated.
// Production follows one-process-one-core.
//
// Order iron law: SetHomeDir/SetConfig point mihomo at the App
// Group BEFORE anything touches C.Path.Cache() — bbolt must never be opened
// at the default location inside the sandbox.
func Setup(options *SetupOptions) error {
	setupMu.Lock()
	defer setupMu.Unlock()

	if options == nil {
		return bridgeSafeError(errors.New("hako: Setup called with nil options"))
	}
	if options.BasePath == "" || options.WorkingPath == "" || options.TempPath == "" {
		return bridgeSafeError(errors.New("hako: SetupOptions.BasePath, WorkingPath and TempPath are required"))
	}
	requestedRuntimeProfile, err := normalizeRuntimeProfile(options.RuntimeProfile)
	if err != nil {
		return bridgeSafeError(err)
	}
	if activeCoreCount.Load() > 0 && requestedRuntimeProfile != currentRuntimeProfile() {
		return bridgeSafeError(fmt.Errorf(
			"hako: changing RuntimeProfile from %q to %q requires restart",
			currentRuntimeProfile().String(),
			requestedRuntimeProfile.String(),
		))
	}
	startupPhase("setup:entered")
	requestedCertificateStore, err := ca.ParseStore(options.CertificateStore)
	if err != nil {
		return bridgeSafeError(fmt.Errorf("hako: SetupOptions.CertificateStore: %w", err))
	}
	// Applied before anything that could dial, because GetCertPool builds the pool on
	// first use and every later TLS client shares that instance.
	ca.SetStore(requestedCertificateStore)

	startupPhase("setup:cert-store")
	applyGVisorTCPBufferOverride(options.BasePath)
	if options.DisablePersistentCache {
		if err := cachefile.DisablePersistentCache(); err != nil {
			return bridgeSafeError(fmt.Errorf("hako: disable persistent cache: %w", err))
		}
		setupCacheDisabled = true
	}
	if err := validateTunMTU(options.TunMTU); err != nil {
		return bridgeSafeError(err)
	}
	requestedTunMTU := normalizedTunMTU(options.TunMTU)
	if activeCoreCount.Load() > 0 && requestedTunMTU != effectiveTunMTU() {
		return bridgeSafeError(fmt.Errorf("hako: changing TunMTU from %d to %d requires restart", effectiveTunMTU(), requestedTunMTU))
	}

	startupPhase("setup:mtu-checked")
	// tz shim first so every timestamp below is already correct.
	if options.TimeZone != "" {
		if err := applyTimeZone(options.TimeZone); err != nil {
			return bridgeSafeError(fmt.Errorf("hako: apply timezone %q: %w", options.TimeZone, err))
		}
	}

	// SetTraceback is process-wide. SetPanicOnFault is intentionally not used:
	// it only affects the calling goroutine, while the core runs on different
	// goroutines, so enabling it here would promise crash coverage it cannot
	// provide.
	//
	// Darwin crash reports are NOT authoritative for faults raised in Go code, and
	// this comment used to claim they were. Measured: gomobile builds Apple targets
	// as a c-archive, so fatalpanic does reach crash() and an .ips report is
	// produced -- but Apple's frame-pointer unwinder cannot walk Go stacks, so every
	// thread in that report terminates at runtime.asmcgocall.abi0, the word "panic"
	// never appears, and the report says only that the Go runtime called raise().
	// The traceback itself goes to fd 2, and fd 2 in a system-launched app extension
	// is /dev/null. So the traceback needs a destination of its own; see
	// armGoCrashOutputAt.
	startupPhase("setup:timezone")
	tracebackOnce.Do(func() {
		debug.SetTraceback("all")
	})

	// Memory trio for the ~50MB NE jetsam budget,
	// mirroring libbox's minimal recipe (SetGCPercent(10)+SetMemoryLimit):
	//  1. soft limit at 3/4 of the budget, leaving headroom for cgo/ObjC
	//     allocations the Go runtime cannot see;
	//  2. aggressive GC (10% growth vs default 100%) to keep RSS low;
	//  3. the with_low_memory build tag halves pool buffers (compile-time,
	//     verified via features.WithLowMemory).
	// Proactive release + connection reset under real pressure.
	if options.MemoryLimit > 0 {
		softLimit := options.MemoryLimit * 3 / 4
		debug.SetMemoryLimit(softLimit)
		debug.SetGCPercent(10)
		currentRuntimeSetup.softMemoryLimit = softLimit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		currentRuntimeSetup.gcPercent = 10
	} else {
		// Setup is the session bootstrap: without a limit in these options
		// there is no configured limit, whatever an earlier Setup or a
		// service-time pacing default wrote here. Left in place, a stale
		// value arms the Setup-time threshold monitor below with a limit the
		// machine must not use (the pacing value's trigger sits under this
		// workload's measured resident steady state), and it does so before
		// NewService can re-arm with the correct budget. The service-time
		// default re-derives the runtime limit from the platform.
		currentRuntimeSetup.softMemoryLimit = 0
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		// And the runtime itself, not only the mirror: leaving the previous
		// session's GOMEMLIMIT running while diagnostics report none would
		// have macOS and app-process re-Setups paced by a limit nothing
		// declares. MaxInt64 is the runtime's own no-limit value.
		debug.SetMemoryLimit(math.MaxInt64)
	}

	// GOMAXPROCS cap: automaxprocs is a no-op without cgroups
	// (iOS), so Go otherwise runs NumCPU (~6 on modern iPhones) OS threads,
	// each with its own stack. Cap to save that RAM under the NE budget.
	if procs := effectiveMaxProcs(options); procs > 0 {
		runtime.GOMAXPROCS(procs)
	}

	startupPhase("setup:runtime-tuned")
	// Path wiring — BEFORE any C.Path consumer runs.
	C.SetHomeDir(options.WorkingPath)
	C.SetConfig(filepath.Join(options.WorkingPath, "config.yaml"))
	setupStartupPhaseLogPath = options.StartupPhaseLogPath
	if setupStartupPhaseLogPath == "" {
		setupStartupPhaseLogPath = filepath.Join(options.WorkingPath, "hako-core-phases.log")
	}
	setupClashAPIPath = filepath.Join(options.BasePath, clashAPISocketName)
	setupOOMEvidencePath = filepath.Join(options.BasePath, oomEvidenceFileName)
	setupGoCrashReportBasePath = options.BasePath
	// Remove the pre-existing pathname before the new listener starts. It is
	// safe to ignore errors: startClashAPI still owns validation/readiness.
	//
	// Asked of the REQUESTED profile rather than currentRuntimeProfile(), because
	// the store that commits it is ~35 lines below this one -- reading the live
	// value here would answer with the previous Setup's profile, which on the
	// first Setup of a process is the zero value, iOS. A policy read placed before
	// the policy is committed is the kind of correct-looking line that answers a
	// question about the wrong run.
	//
	// A profile that binds no socket never created one of these either, so there
	// is nothing here to clean up and the remove is skipped rather than left to
	// fail silently.
	legacyClashAPIPath := filepath.Join(options.WorkingPath, clashAPISocketName)
	if runtimePolicyFor(requestedRuntimeProfile, true).bindsUnixControlSocket &&
		legacyClashAPIPath != setupClashAPIPath {
		_ = os.Remove(legacyClashAPIPath)
	}

	startupPhase("setup:paths-wired")
	// Pre-create + write-probe every directory the core assumes exists.
	// WorkingPath itself hosts cache.db (C.Path.Cache()) and the fakeip
	// persistence inside it.
	for _, dir := range []string{
		options.WorkingPath,
		options.TempPath,
		filepath.Join(options.WorkingPath, "providers"),
		filepath.Join(options.WorkingPath, "geodata"),
	} {
		if err := probeDir(dir); err != nil {
			return bridgeSafeError(err)
		}
	}

	startupPhase("setup:dirs-probed")
	// Give the Go runtime somewhere to write a traceback, now that BasePath is known
	// to be writable. Deliberately non-fatal: losing post-mortem visibility is worse
	// than starting without it, but it is not a reason to refuse to start a tunnel.
	// Any traceback the previous run left behind is archived here, not truncated.
	if err := armGoCrashOutputAt(options.BasePath); err != nil {
		logrus.Warnf("[iOS] Go crash output unavailable, a panic will leave no readable traceback: %v", err)
	}

	startupPhase("setup:crash-armed")
	logMaxLines := options.LogMaxLines
	if logMaxLines <= 0 {
		logMaxLines = defaultLogMaxLines
	}
	recentLogs.setMax(logMaxLines)
	currentRuntimeSetup.logMaxLines = logMaxLines
	setTunMTU(requestedTunMTU)
	setupRuntimeProfile.Store(uint32(requestedRuntimeProfile))
	// Arm the process-lifetime GCD source only after evidence paths and the
	// RuntimeProfile are committed. This is independent of MemoryLimit: macOS
	// Network Extensions deliberately keep the Go runtime defaults, and the
	// notification is still worth having because it wakes the threshold machine.
	// No-op off darwin/cgo.
	armMemoryPressureMonitorForRuntime(
		requestedRuntimeProfile,
		options.DisablePersistentCache,
		startMemoryPressureMonitor,
	)
	// The threshold machine polls on its own schedule and is what decides to act; the OS
	// notification only pokes it. Armed
	// under the same profile gate, and reporting rather than acting unless explicitly enabled.
	armMemoryPressureMonitorForRuntime(
		requestedRuntimeProfile,
		options.DisablePersistentCache,
		func() {
			// Shedding is the default now, as it is upstream. Report-only was a
			// staged rollout whose own log line named its enabling criterion --
			// "the count that decides whether shedding is worth enabling" -- and
			// three rounds of device evidence answered it: nineteen triggers,
			// three jetsam kills, zero sheds. The machine saw every death coming
			// and was allowed to do nothing. MemoryPressureShed stays readable
			// for compatibility but no longer gates the action.
			// The machine's limit is the FULL configured budget: its samples
			// are process footprint and its margins are calibrated against the
			// real budget. The 3/4 soft limit is GC pacing, a different unit;
			// against a 50 MiB budget it would put the trigger at 32.5 MiB,
			// below the measured 42 MiB resident steady state.
			startPressureThresholdMonitor(options.MemoryLimit, true)
		},
	)
	startupPhase("setup:monitors-armed")
	setupDone = true
	return nil
}

// effectiveMaxProcs resolves the GOMAXPROCS cap: explicit MaxProcs
// wins; otherwise cap at 4 when memory-constrained (NE); otherwise 0 (leave
// the Go default untouched, e.g. macOS/app process). Never exceeds NumCPU.
func effectiveMaxProcs(options *SetupOptions) int {
	const constrainedCap = 4
	procs := options.MaxProcs
	if procs <= 0 {
		if options.MemoryLimit <= 0 {
			return 0
		}
		procs = constrainedCap
	}
	if n := runtime.NumCPU(); procs > n {
		procs = n
	}
	return procs
}

// probeDir creates dir and proves it is writable now, so misconfigured App
// Group paths fail Setup with a readable error instead of surfacing later
// as an opaque bbolt/provider failure mid-Start.
func probeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hako: create %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".hako-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("hako: %s is not writable: %w", dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("hako: cleanup probe in %s: %w", dir, err)
	}
	return nil
}

// applyTimeZone installs Hako's presentation location without mutating
// time.Local. The Go time package reads time.Local without synchronization,
// so assigning it after a gomobile framework has loaded races with runtime,
// SDK and test timers. LoadLocation resolves against embedded tzdata.
func applyTimeZone(id string) error {
	loc, err := time.LoadLocation(id)
	if err != nil {
		return err
	}
	timeZoneMu.Lock()
	defer timeZoneMu.Unlock()
	if configuredTimeZone != "" {
		if configuredTimeZone == id {
			return nil
		}
		return fmt.Errorf("changing timezone from %q to %q requires process restart", configuredTimeZone, id)
	}
	configuredLocation.Store(loc)
	configuredTimeZone = id
	return nil
}

func hakoLocalTime(value time.Time) time.Time {
	if location := configuredLocation.Load(); location != nil {
		return value.In(location)
	}
	return value
}

// logChannelSize bounds the in-flight log buffer. Beyond it, lines are
// dropped rather than blocking the core.
const logChannelSize = 1024

// logLine is one message on its way to the drain goroutine. delivered is
// non-nil only for startup lines: it is closed once the platform call for
// this line has returned, which is what lets Write promise the line has left
// this process.
type logLine struct {
	message   string
	delivered chan struct{}
}

// startupDeliveryBudget bounds how long one startup line may wait to be
// handed over. A healthy platform takes a line in microseconds; this much
// waiting means the consumer is gone, and the budget is spent at most once —
// the writer then gives up on confirmed delivery for the rest of its life
// rather than turning a few hundred startup lines into minutes of stall.
const startupDeliveryBudget = 500 * time.Millisecond

// platformLogWriter forwards logrus output line-wise to the platform with
// backpressure protection: Write never blocks the core's
// logging goroutine for longer than one bounded startup wait. Lines go to a
// buffered channel drained by a dedicated goroutine; when a slow Swift
// WriteLog fills the buffer, further lines are dropped and counted (mihomo's
// logCh is unbuffered — a blocking consumer would stall the core,
// log/log.go:13).
//
// While the tunnel is starting, Write additionally waits — boundedly — until
// the drain goroutine has handed the line to the platform. Startup lines are
// the ones that explain a kill: an iOS packet tunnel that crosses its memory
// budget is SIGKILLed, and anything still queued in this process dies with
// it, leaving the reader "the VPN tunnel provider stopped unexpectedly" while
// the lines that said why were still in memory. The wait stays on the one
// channel so lines keep their order, and it is acknowledged delivery rather
// than a bypass: bypassing the channel only moved the loss to the next queue.
type platformLogWriter struct {
	platform PlatformInterface
	ch       chan logLine
	done     chan struct{}
	stopped  chan struct{}
	close    sync.Once
	dropped  atomic.Int64
	// True until the tunnel is up. While set, Write waits for delivery.
	startingUp atomic.Bool
	// Set when a startup line has waited its whole budget and the platform
	// still had not taken it. From then on the writer behaves as established:
	// the guarantee is gone, and waiting again would not bring it back.
	platformStalled atomic.Bool
}

func (w *platformLogWriter) Write(p []byte) (int, error) {
	// The line as the core wrote it (2026-08-21 ruling). A log a reader
	// cannot read is not a diagnostic, and the reader's own configuration
	// already sits on this device byte for byte, credentials included -- so
	// scrubbing the log bought nothing it did not also cost. What guards a
	// share is the export flow telling the reader what is in the file.
	if msg := strings.TrimRight(string(p), "\n"); msg != "" {
		recentLogs.add(msg) // in-memory ring buffer for the logs getter
		select {
		case <-w.done:
			return len(p), nil
		default:
		}
		if w.startingUp.Load() && !w.platformStalled.Load() {
			w.writeStartup(msg)
			return len(p), nil
		}
		select {
		case w.ch <- logLine{message: msg}:
		case <-w.done:
		default:
			w.dropped.Add(1) // buffer full: drop rather than block the core
		}
	}
	return len(p), nil
}

// writeStartup queues one line and waits until the platform has taken it, or
// until the budget says the platform is not going to. The line still goes
// through the ordinary channel — order is kept, and if the platform revives
// later the line is written, merely no longer waited for.
func (w *platformLogWriter) writeStartup(msg string) {
	delivered := make(chan struct{})
	budget := time.NewTimer(startupDeliveryBudget)
	defer budget.Stop()
	select {
	case w.ch <- logLine{message: msg, delivered: delivered}:
	case <-budget.C:
		// The buffer itself is full behind a consumer that is not draining.
		w.platformStalled.Store(true)
		w.dropped.Add(1)
		return
	case <-w.done:
		return
	}
	select {
	case <-delivered:
	case <-budget.C:
		w.platformStalled.Store(true)
	case <-w.done:
	}
}

func (w *platformLogWriter) drain() {
	defer close(w.stopped)
	for {
		select {
		case line := <-w.ch:
			w.platform.WriteLog(line.message)
			if line.delivered != nil {
				close(line.delivered)
			}
		case <-w.done:
			if dropped := w.dropped.Load(); dropped > 0 {
				recentLogs.add(fmt.Sprintf("[hako] dropped %d log lines due to platform backpressure", dropped))
			}
			return
		}
	}
}

func (w *platformLogWriter) Close() {
	w.close.Do(func() { close(w.done) })
}

var (
	logRedirectMu         sync.Mutex
	activeLogWriter       *platformLogWriter
	localLogFormatterOnce sync.Once
)

type localLogFormatter struct {
	delegate logrus.Formatter
}

func (formatter *localLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	localized := *entry
	localized.Time = hakoLocalTime(entry.Time)
	return formatter.delegate.Format(&localized)
}

// redirectLogs sends mihomo's logrus stream to platform.WriteLog, buffered so
// a slow consumer cannot stall the core.
func redirectLogs(platform PlatformInterface) *platformLogWriter {
	w := &platformLogWriter{
		platform: platform,
		ch:       make(chan logLine, logChannelSize),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	w.startingUp.Store(true)
	go w.drain()
	localLogFormatterOnce.Do(func() {
		logger := logrus.StandardLogger()
		logger.SetFormatter(&localLogFormatter{delegate: logger.Formatter})
	})

	logRedirectMu.Lock()
	previous := activeLogWriter
	activeLogWriter = w
	logrus.SetOutput(w)
	logRedirectMu.Unlock()
	if previous != nil {
		previous.Close()
	}
	return w
}

func stopLogRedirect(w *platformLogWriter) {
	if w == nil {
		return
	}
	logRedirectMu.Lock()
	if activeLogWriter == w {
		activeLogWriter = nil
		logrus.SetOutput(io.Discard)
	}
	logRedirectMu.Unlock()
	w.Close()
}

// markTunnelEstablished returns logging to the buffered path once the tunnel is
// running and throughput matters more than surviving a kill.
func (w *platformLogWriter) markTunnelEstablished() {
	if w != nil {
		w.startingUp.Store(false)
	}
}
