package hako

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/component/pause"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/config"
	constant "github.com/TokenPLS/Hako/constant"
	provider "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/hub/executor"
	coreListener "github.com/TokenPLS/Hako/listener"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/TokenPLS/Hako/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

var errNotImplemented = errors.New("hako: not implemented yet")

// activeCoreCount protects startup-only process invariants (currently MTU)
// against a second Setup call while gVisor still owns the old values.
var activeCoreCount atomic.Int32

// BoxService is one active mihomo core session. The provider may stop and
// start it again in the same process; concurrent cores remain unsupported.
type BoxService struct {
	mu        sync.Mutex
	routingMu sync.Mutex
	platform  PlatformInterface
	running   bool
	// STUN sessions execute against the live proxy table. They are registered
	// separately from mu so Close/Reload can cancel them before waiting for the
	// bounded session to release mu and mutate global mihomo state.
	stunMu       sync.Mutex
	stunClosing  bool
	stunNextID   uint64
	stunSessions map[uint64]context.CancelFunc
	stunWG       sync.WaitGroup
	// tunFd holds the dup'd PacketFlow bridge fd while the core owns it but sing-tun has
	// not yet taken ownership; -1 once handed off or never opened.
	tunFd int
	// liveTunFd remembers the bridge fd VALUE sing-tun is running on (survives the
	// ownership handoff), so Reload can re-inject the same fd and keep
	// tun.Equal true — no tunnel teardown. -1 when no tun.
	liveTunFd int
	// liveTun is the complete effective tun handed to sing-tun. Reload must
	// match it exactly (including the same fd) or it would tear down the utun.
	liveTun    LC.Tun
	hasLiveTun bool
	// ifaceListener is the NWPathMonitor callback registered with the
	// platform during Start; unregistered on Close.
	ifaceListener         InterfaceUpdateListener
	logWriter             *platformLogWriter
	clashAPIPath          string
	startTimeUnix         int64
	inboundCount          int32
	outboundCount         int32
	dnsTransports         dnsTransportSnapshot
	outboundEndpointKinds map[string]string
	providerRuntime       *providerRuntime
	proxyShare            *proxyShareRuntime
	pauseCount            atomic.Uint64
	wakeCount             atomic.Uint64

	// The memory judge's inputs and its last answer (reload_memory_guard.go): the footprint
	// before the running configuration was parsed, the length of the configuration that is
	// running, and the verdict on the last reload. All under s.mu.
	startFootprintBytes    int64
	configLength           int
	providerBytes          int64
	candidateProviderBytes int64
	reloadVerdict          reloadMemoryVerdict

	// endPauseTimer bounds an iOS pause so it cannot outlive a missing wake callback.
	endPauseMu    sync.Mutex
	endPauseTimer *time.Timer
	// flowGeneration and flowPlans belong only to the macOS Transparent
}

// NewService binds the platform callbacks and returns the (not yet started)
// service. Requires Setup to have succeeded; from this point mihomo's log
// stream flows to platform.WriteLog.
func NewService(platform PlatformInterface) (*BoxService, error) {
	if platform == nil {
		return nil, bridgeSafeError(errors.New("hako: NewService requires a platform"))
	}
	setupMu.Lock()
	ok := setupDone
	cacheDisabled := setupCacheDisabled
	setupMu.Unlock()
	if !ok {
		return nil, bridgeSafeError(errors.New("hako: call Setup before NewService"))
	}
	if cacheDisabled {
		return nil, bridgeSafeError(errors.New("hako: NewService is unavailable after App-only DisablePersistentCache Setup"))
	}
	// From here every platform callback goes through the sanitizing
	// decorator, so a log line or message holding invalid UTF-8 is repaired
	// before it crosses the bridge (see bridgeSafeString).
	platform = bridgeSafePlatform(platform)
	logWriter := redirectLogs(platform)
	armNEPacingForService(platform)
	// Bind outbound sockets to the physical interface via the platform
	// cleared when the platform opts out.
	installSocketHook(platform)
	// Give inbound listeners their loopback face back under the Network
	// Extension socket scope; cleared in app processes, which have no scope.
	installListenerScopeHooks(platform.UnderNetworkExtension())
	return &BoxService{platform: platform, tunFd: -1, liveTunFd: -1, logWriter: logWriter}, nil
}

// Start parses configContent (full mihomo YAML; no tun stanza) and
// brings the core up through the typed raw-config pipeline → overrideForIOS
// → ApplyConfig.
// The two-phase fd handoff slots between parse and override.
//
// Parse+apply run on a Go-managed goroutine, not the calling thread —
// gomobile calls arrive on Darwin threads with small fixed stacks, and
// config parsing recurses deeply. Start itself blocks until the core is
// Running (or parse failed), so callers get a definite outcome.
// logFootprint records the jetsam metric at a named point in startup.
//
// An iOS packet tunnel gets fifty megabytes for the whole extension and is
// SIGKILLed the moment it crosses. When that happens there is no error, no
// crash report and no chance to explain — the reader is told the tunnel
// "stopped unexpectedly" and we are left reconstructing it from JetsamEvent
// files. These lines are what turns that into a readable answer: they say how
// much of the budget each stage of startup had spent, and they reach disk
// synchronously, so the last one before a kill survives it.
func logFootprint(stage string) {
	footprint := MemoryFootprint()
	if footprint <= 0 {
		return
	}
	log.Infoln("[mem] %s: %.1f MiB of the extension's budget",
		stage, float64(footprint)/(1<<20))
}

func (s *BoxService) Start(configContent string) error {
	// The exported surface is a thin shell so the error crossing the gomobile
	// bridge always passes bridgeSafeError; the body below keeps its named
	// result for the deferred startup breadcrumb. The shell carries no doc
	// comment on purpose: gomobile copies doc comments into the generated
	// public header, and this note is an implementation detail.
	return bridgeSafeError(s.start(configContent))
}

func (s *BoxService) start(configContent string) (startErr error) {
	// Every failing return leaves its reason in the startup breadcrumb -- the
	// one account that survives the process -- so the reader's next launch can
	// say why instead of relaying the platform's empty code=12. A deferred
	// stamp rather than per-site calls: the next failure mode will not be the
	// last one, and it must not need its own call site to be tellable.
	// recordStartupFailure no-ops on nil and outside the recording window.
	defer func() { recordStartupFailure(startErr) }()
	startupPhase("start-first-statement")
	defer armStartupProbes()()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("hako: service already started")
	}
	if err := validateConfigurationInput(configContent); err != nil {
		return err
	}
	// Serialize the transition from setup-time parameters into a starting
	// core with Setup itself. Without this short lock, a concurrent Setup
	// could pass activeCoreCount==0 and change MTU after this Start snapshots
	// the old value but before gVisor becomes running.
	startupPhase("validated")
	setupMu.Lock()
	activeCoreCount.Add(1)
	setupMu.Unlock()
	startupPhase("core-count-bumped")
	defer func() {
		if !s.running {
			activeCoreCount.Add(-1)
		}
	}()
	if s.logWriter == nil {
		s.logWriter = redirectLogs(s.platform)
	}
	startupPhase("logs-redirected")
	// Match libbox's StartStateInitialize ordering: the platform interface
	// monitor is a hard prerequisite and must publish the current physical
	// path before ApplyConfig can create DNS/proxy transports. Continuing after
	// a monitor failure would permit stale or unscoped first dials.
	logFootprint("before the interface monitor")
	startupPhase("pre-iface-monitor")
	listener, err := startInterfaceMonitor(s.platform)
	if err != nil {
		return fmt.Errorf("hako: start default interface monitor: %w", err)
	}
	s.ifaceListener = listener
	startupPhase("iface-monitor-up")

	var startedDNSTransports dnsTransportSnapshot
	startedOutboundEndpointKinds := snapshotOutboundEndpointKinds(configContent)
	var startedProviderRuntime *providerRuntime
	done := make(chan error, 1)
	var pendingTunOpen chan tunOpenResult
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// ApplyConfig may panic before or after sing-tun accepts the fd.
				// Shutdown first, then close only if it is still open.
				executor.WaitBeforeTunAttach = nil
				shutdownCore()
				stopClashAPI(s.clashAPIPath)
				s.clashAPIPath = ""
				closeFDIfOpen(s.tunFd)
				s.resetTunState()
				reapUnclaimedTunOpen(pendingTunOpen)
				if startedProviderRuntime != nil {
					startedProviderRuntime.close()
					startedProviderRuntime = nil
				}
				// A panic is the one failure a user is most likely to meet as
				// "nothing happened", so it is the one that most needs a line.
				log.Errorln("[Apple] the start panicked and the tunnel did not come up: %v", r)
				done <- fmt.Errorf("hako: start panicked: %v", r)
			}
		}()
		startupPhase("pre-config-parse")
		// The baseline the reload judge measures one core against. Emptied first: on a
		// restart in the same process the previous core is garbage until collected, and a
		// baseline that included it would make the running core look smaller than it is.
		debug.FreeOSMemory()
		s.startFootprintBytes = readFootprintForReload()
		s.configLength = len(configContent)
		s.providerBytes = providerPayloadBytes(configContent)
		logFootprint("before parsing the configuration")
		cfg, runtime, err := parseConfigForIOSRuntime(configContent, s.platform.UnderNetworkExtension(), deviationEntryStart)
		logFootprint("after parsing the configuration")
		startupPhase("config-parsed")
		if err != nil {
			// A phase marker as well as a log line, and the pair is the point.
			//
			// On 2026-08-28 the macOS lane found the log string present in the
			// shipped binary and never emitted: the phase record stopped at
			// config-parsed, the core log ended on the footprint above, and a
			// deliberately broken YAML still produced a Disconnected tunnel
			// with no stated reason. Two explanations fit that -- the parse did
			// not error, or the error was logged somewhere the reader cannot
			// see -- and one line of prose cannot tell them apart.
			//
			// The phase record and the core log are different sinks, written by
			// different code, and phases were reaching the file. So the refusal
			// writes to BOTH. Whichever one shows up says which explanation is
			// right, without anybody guessing.
			startupPhase("config-refused")
			// Say why, in the core's own log, before handing the error up.
			//
			// Until 2026-08-28 this returned in silence: the phase record
			// stopped at config-parsed, the core log's last line was the
			// footprint above, and the extension's unified log had nothing. A
			// start that fails and leaves no readable reason is "I tapped it and
			// nothing happened" -- found by the macOS lane while trying to
			// attribute seven device results and unable to tell a refusal from a
			// crash.
			//
			// Verbatim,: the core logs what the core decided, with no
			// redaction and no rewording. Whether the App surfaces it is the
			// client's half; the core's half is not being silent.
			log.Errorln("[Apple] the configuration was refused and the tunnel did not start: %v", err)
			done <- err
			return
		}
		startedProviderRuntime = runtime
		fail := func(err error) {
			// Same reason as the refusal above: every way this start can end
			// badly has to leave a line behind.
			log.Errorln("[Apple] the tunnel did not start: %v", err)
			if startedProviderRuntime != nil {
				startedProviderRuntime.close()
				startedProviderRuntime = nil
			}
			done <- err
		}

		underNE := s.platform.UnderNetworkExtension()
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		startedDNSTransports = snapshotDNSTransports(cfg)
		startupPhase("config-finalized")

		// PacketFlow bridge handoff: when the config asks for tun, the
		// core-facing bridge fd is pulled from the platform and injected before
		// sing-tun starts -- but no longer before ApplyConfig. The options
		// handed to OpenTun are final here (finalizeConfigForApple has run, so
		// there is no raw-versus-finalized divergence to fear), and Apple's
		// setTunnelNetworkSettings inside it costs ~316ms during which this
		// goroutine used to sit idle. It now runs concurrently while
		// ApplyConfig loads providers, and executor.WaitBeforeTunAttach joins
		// the two immediately before the listeners and the tun attach, which
		// are the first steps that need the descriptor. A panic from the join
		// aborts the apply through the recover above; an fd that arrives after
		// an abort is closed by the reaper. No-tun configs skip all of it.
		if cfg.General.Tun.Enable {
			startupPhase("tun-open-dispatched")
			pendingTunOpen = dispatchTunOpen(s.platform, &cfg.General.Tun)
			executor.WaitBeforeTunAttach = func(applied *config.Config) {
				result := <-pendingTunOpen
				pendingTunOpen = nil
				if result.err != nil {
					panic(fmt.Sprintf("hako: OpenTun: %v", result.err))
				}
				s.tunFd = result.fd
				s.liveTunFd = result.fd
				applied.General.Tun.FileDescriptor = result.fd
				startupPhase("tun-fd-ready")
			}
		}

		// ApplyConfig drives tunnel status Suspend → InnerLoading → Running.
		// It does not start a controller; after tun verification below, Hako
		// explicitly starts only its binding-owned App Group Unix API.
		startupPhase("pre-apply-config")
		logFootprint("before applying it (providers load here)")
		executor.ApplyConfig(cfg, true)
		// The control plane is NOT created here. It used to be, and the second creation below
		// replaced it -- route.ReCreateServer swaps the whole listener set. One start, one call.
		executor.WaitBeforeTunAttach = nil
		logFootprint("after applying it")
		startupPhase("apply-config-done")
		// Past here a kill is a runtime event and the log already explains the
		// start; buffering can resume.
		s.logWriter.markTunnelEstablished()
		pendingTunFd := s.tunFd
		// Ownership has now either moved to sing-tun or the listener rejected
		// it. Do not let Close/panic paths blindly close a core-owned fd.
		s.tunFd = -1
		if cfg.General.Tun.Enable {
			if err := verifyTunStarted(cfg.General.Tun); err != nil {
				shutdownCore()
				closeFDIfOpen(pendingTunFd)
				s.resetTunState()
				fail(err)
				return
			}
			startupPhase("tun-verified")
		}
		if cfg.General.Tun.Enable {
			s.liveTun = cfg.General.Tun
			s.hasLiveTun = true
		}
		if underNE {
			s.clashAPIPath = ClashAPIPath()
			if err := startControlPlane(cfg, s.clashAPIPath); err != nil {
				shutdownCore()
				s.resetTunState()
				s.clashAPIPath = ""
				fail(err)
				return
			}
			startupPhase("clash-api-up")
		} else {
			// Outside the extension there is no App Group socket to own or wait on, only the
			// user's controller if they configured one. Same single call, no readiness poll.
			applyExternalController(cfg)
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		s.closeInterfaceMonitor()
		return err
	}

	startupPhase("start-return-begin")
	s.running = true
	// Startup finished, so the breadcrumb has nothing to report and the recorder comes off
	// the geo loaders. A record left behind here would have the next launch tell the reader
	// their tunnel was killed when it was not.
	markStartupComplete()
	s.resumeSTUNSessions()
	s.startTimeUnix = time.Now().Unix()
	s.inboundCount = runtimeInboundCount()
	s.outboundCount = int32(len(tunnel.Proxies()))
	s.dnsTransports = startedDNSTransports
	s.outboundEndpointKinds = startedOutboundEndpointKinds
	s.providerRuntime = startedProviderRuntime
	setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
	publishCoreService(s)
	startupPhase("start-return-done")
	return nil
}

type tunOpenResult struct {
	fd  int
	err error
}

// dispatchTunOpen runs prepareTunBridgeFD on its own goroutine and hands back
// the channel its single result will arrive on. The caller either claims the
// result (the WaitBeforeTunAttach join) or, on an abort, passes the channel to
// reapUnclaimedTunOpen so a descriptor that arrives after the abort is closed
// instead of leaked.
func dispatchTunOpen(platform PlatformInterface, tun *LC.Tun) chan tunOpenResult {
	results := make(chan tunOpenResult, 1)
	options := tun
	go func() {
		fd, err := prepareTunBridgeFD(platform, options)
		results <- tunOpenResult{fd: fd, err: err}
	}()
	return results
}

func reapUnclaimedTunOpen(pending chan tunOpenResult) {
	if pending == nil {
		return
	}
	go func() {
		if result := <-pending; result.err == nil {
			closeFDIfOpen(result.fd)
		}
	}()
}

// prepareTunBridgeFD asks Swift to apply network settings, start the public
// PacketFlow adapter, and return its core-facing SOCK_DGRAM fd. The duplicate
// gives sing-tun independent ownership while Swift retains the original for
// deterministic adapter cancellation.
func prepareTunBridgeFD(platform PlatformInterface, tun *LC.Tun) (int, error) {
	fd, err := platform.OpenTun(newTunOptions(tun))
	if err != nil {
		return -1, fmt.Errorf("hako: OpenTun: %w", err)
	}
	if fd < 0 {
		return -1, fmt.Errorf("hako: OpenTun returned invalid bridge fd %d", fd)
	}
	dupFd, err := unix.Dup(int(fd))
	if err != nil {
		return -1, fmt.Errorf("hako: dup PacketFlow bridge fd %d: %w", fd, err)
	}
	return dupFd, nil
}

func verifyTunStarted(expected LC.Tun) error {
	actual := coreListener.GetTunConf()
	if !actual.Enable {
		return errors.New("hako: tun listener failed to start; inspect preceding core log for the underlying error")
	}
	if actual.FileDescriptor != expected.FileDescriptor {
		return fmt.Errorf("hako: tun listener fd mismatch: live=%d expected=%d", actual.FileDescriptor, expected.FileDescriptor)
	}
	return nil
}

func closeFDIfOpen(fd int) {
	if fd < 0 {
		return
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		_ = unix.Close(fd)
	}
}

func (s *BoxService) resetTunState() {
	s.tunFd = -1
	s.liveTunFd = -1
	s.liveTun = LC.Tun{}
	s.hasLiveTun = false
}

// Reload hot-swaps the configuration without dropping the tunnel. The utun is
// preserved by re-injecting the SAME live fd so the listener's tun.Equal holds
// and the tunnel is not torn down. ApplyConfig runs with
// force=false so unchanged listeners (the tun) are reused rather than rebuilt.
// Forgetting the re-injection would make tun.Equal false → rebuild → drop.
func (s *BoxService) Reload(configContent string) error {
	if err := validateConfigurationInput(configContent); err != nil {
		return bridgeSafeError(err)
	}
	// A selected adapter can be replaced or closed by ApplyConfig. Cancel and
	// drain the bounded diagnostic before entering the config transaction.
	s.stopSTUNSessions()
	defer s.resumeSTUNSessions()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return bridgeSafeError(errors.New("hako: Reload before Start"))
	}
	// Before anything of the candidate is built: would one more core fit? See
	// reload_memory_guard.go for why the answer can be no and what the App does with it.
	verdict := s.judgeReloadAgainstTheCeiling(configContent)
	if verdict.Reason == reloadRefusedMemory {
		return bridgeSafeError(reloadMemoryRefusal(verdict))
	}
	// From here a second core is being built. Leave the marker that outlives this process
	// if the build is what kills it, and take it back on the way out whatever happened.
	ticket := beginReloadEvidence(verdict)
	defer endReloadEvidence(ticket)
	done := make(chan error, 1)
	go func() {
		var nextProviderRuntime *providerRuntime
		committedProviderRuntime := false
		defer func() {
			if r := recover(); r != nil {
				if !committedProviderRuntime && nextProviderRuntime != nil {
					nextProviderRuntime.close()
					nextProviderRuntime = nil
				}
				// A panic is the one failure a user is most likely to meet as
				// "nothing happened", so it is the one that most needs a line.
				log.Errorln("[Apple] the reload panicked and the tunnel did not come up: %v", r)
				done <- fmt.Errorf("hako: reload panicked: %v", r)
			}
		}()
		underNE := s.platform.UnderNetworkExtension()
		cfg, runtime, err := parseConfigForIOSRuntime(configContent, underNE, deviationEntryReload)
		if err != nil {
			// A reload that is refused leaves the running configuration in
			// place, so nothing visibly breaks and nothing visibly happens
			// either -- which is exactly when a silent failure costs the most.
			log.Errorln("[Apple] the replacement configuration was refused and the running one is unchanged: %v", err)
			done <- err
			return
		}
		nextProviderRuntime = runtime
		fail := func(err error) {
			log.Errorln("[Apple] the reload did not complete and the running configuration is unchanged: %v", err)
			if nextProviderRuntime != nil {
				nextProviderRuntime.close()
				nextProviderRuntime = nil
			}
			done <- err
		}
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		if cfg.General.Tun.Enable {
			if s.liveTunFd < 0 {
				fail(errors.New("hako: reload enables tun but no live fd from Start"))
				return
			}
			cfg.General.Tun.FileDescriptor = s.liveTunFd
		}
		if cfg.General.Tun.Enable != s.hasLiveTun {
			fail(errors.New("hako: reload cannot enable or disable the live tun; restart the appex"))
			return
		}
		if s.hasLiveTun && !tunConfigurationsEqual(s.liveTun, cfg.General.Tun) {
			fail(errors.New("hako: reload changes the effective tun; restart the appex instead of rebuilding utun"))
			return
		}
		advanceReloadEvidence(ticket, reloadPhaseApply)
		func() {
			s.routingMu.Lock()
			defer s.routingMu.Unlock()
			executor.ApplyConfig(cfg, false)
			applyExternalController(cfg)
		}()
		if err := s.reapplyProxyShareLocked(); err != nil {
			// Core config reload is already committed by ApplyConfig. Keep that
			// transaction successful, but close the ancillary LAN listener
			// fail-closed rather than reporting a false rollback to the App.
			log.Errorln("[iOS] proxy share closed after reload: %v", err)
			_ = s.stopProxyShareLocked()
		}
		previousProviderRuntime := s.providerRuntime
		s.providerRuntime = nextProviderRuntime
		committedProviderRuntime = true
		if previousProviderRuntime != nil {
			previousProviderRuntime.close()
		}
		s.inboundCount = s.runtimeInboundCountLocked()
		s.outboundCount = int32(len(tunnel.Proxies()))
		s.dnsTransports = snapshotDNSTransports(cfg)
		s.outboundEndpointKinds = snapshotOutboundEndpointKinds(configContent)
		s.configLength = len(configContent)
		if s.candidateProviderBytes >= 0 {
			s.providerBytes = s.candidateProviderBytes
		} else {
			s.providerBytes = providerPayloadBytes(configContent)
		}
		setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
		debug.FreeOSMemory()
		done <- nil
	}()
	return bridgeSafeError(<-done)
}

func runtimeInboundCount() int32 {
	count := len(tunnel.Listeners())
	ports := coreListener.GetPorts()
	for _, port := range []int{ports.Port, ports.SocksPort, ports.RedirPort, ports.TProxyPort, ports.MixedPort} {
		if port != 0 {
			count++
		}
	}
	if ports.ShadowSocksConfig != "" {
		count++
	}
	if ports.VmessConfig != "" {
		count++
	}
	if coreListener.GetTuicConf().Enable {
		count++
	}
	if coreListener.GetTunConf().Enable {
		count++
	}
	return int32(count)
}

// runGuardedTeardown runs the async core teardown step, recovering any panic so
// a fault during shutdown cannot propagate out of the goroutine and crash the
// host app across the gomobile boundary. Start's goroutine is already
// recover-wrapped; Close must match.
func runGuardedTeardown(teardown func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[iOS] core teardown recovered from panic: %v", r)
		}
	}()
	teardown()
}

// Close shuts the core down cleanly — listener cleanup + fakeip pool
// persistence via executor.Shutdown — then returns as much memory to the
// OS as possible. Idempotent; a closed service may be Started again
// and the Network Extension now relies on that for in-process restart.
func (s *BoxService) Close() error {
	s.stopSTUNSessions()
	s.releasePauseOnClose()
	s.mu.Lock()
	defer s.mu.Unlock()
	unpublishCoreService(s)
	if !s.running {
		s.stopProxyShareLocked()
		s.closeInterfaceMonitor()
		stopClashAPI(s.clashAPIPath)
		s.clashAPIPath = ""
		stopLogRedirect(s.logWriter)
		s.logWriter = nil
		if s.providerRuntime != nil {
			s.providerRuntime.close()
			s.providerRuntime = nil
		}
		return nil
	}
	// Unregister the interface monitor before tearing the core down.
	s.stopProxyShareLocked()
	s.closeInterfaceMonitor()
	stopClashAPI(s.clashAPIPath)
	s.clashAPIPath = ""
	done := make(chan struct{})
	go func() { // same small-stack rationale as Start
		defer close(done)
		runGuardedTeardown(func() {
			shutdownCore()
			debug.FreeOSMemory()
		})
	}()
	<-done
	if s.providerRuntime != nil {
		s.providerRuntime.close()
		s.providerRuntime = nil
	}
	// Defensive: if a dup fd was opened but never handed to sing-tun
	// (abnormal), don't leak it. On the normal path tunFd is already -1.
	if s.tunFd >= 0 {
		_ = unix.Close(s.tunFd)
		s.tunFd = -1
	}
	s.resetTunState()
	s.running = false
	s.startTimeUnix = 0
	s.inboundCount = 0
	s.outboundCount = 0
	s.dnsTransports = dnsTransportSnapshot{}
	s.outboundEndpointKinds = nil
	activeCoreCount.Add(-1)
	setOOMEvidenceCoreState(false, 0, 0, 0)
	stopLogRedirect(s.logWriter)
	s.logWriter = nil
	return nil
}

func (s *BoxService) closeInterfaceMonitor() {
	if s.ifaceListener == nil {
		return
	}
	listener := s.ifaceListener
	s.ifaceListener = nil
	if err := s.platform.CloseDefaultInterfaceMonitor(listener); err != nil {
		log.Warnln("[iOS] close interface monitor: %v", err)
	}
}

// shutdownCore closes process-global resources that upstream normally leaves
// to process exit. A Network Extension may restart in the same process, so
// finalizers are not an acceptable lifecycle boundary.
func shutdownCore() {
	CloseAllConnections()

	proxies := tunnel.Proxies()
	providers := tunnel.Providers()
	ruleProviders := tunnel.RuleProviders()
	tunnel.UpdateProxies(map[string]constant.Proxy{}, map[string]provider.ProxyProvider{})
	tunnel.UpdateRules(nil, map[string][]constant.Rule{}, map[string]provider.RuleProvider{})

	// Stop TUN/gVisor and reset transports before closing adapters that may
	// still be referenced by an in-flight DNS or packet handler.
	executor.Shutdown()
	resolver.ResetConnection()
	// ResetConnection no longer ends live queries -- it cannot, or every path change would
	// fail the caller's lookup. Shutdown still has to, because this process can host the next
	// core: without this, up to one DNS timeout of goroutines keeps querying upstreams over
	// state that has been torn down.
	resolver.CloseQueries()

	for _, current := range providers {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range ruleProviders {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range proxies {
		_ = current.Close()
	}
}

// RuntimeDiagnosticsJSON returns low-frequency diagnostic metadata. It is a
// BoxService method so Start/Reload/Close and the captured counts share the
// same mutex; it must not be placed on the one-second traffic stream.
func (s *BoxService) RuntimeDiagnosticsJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	connectionCount := int32(0)
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		connectionCount++
		return true
	})
	runtimeSetup := runtimeSetupSnapshot()
	// A soft limit of zero is the absence of one, not a limit of zero -- iOS carries no
	// ceiling of ours by ruling. This map is rendered on a page, where "0" is read as a
	// measurement; the key is therefore present only when something set it.
	memory := currentRuntimeMemorySnapshot()
	nat64 := nat64DiagnosticsSnapshot()
	admission := tunnel.TCPConnectionAdmissionSnapshot()
	diagnostics := map[string]any{
		"processIdentifier":                   os.Getpid(),
		"startTimeUnix":                       s.startTimeUnix,
		"goroutines":                          runtime.NumGoroutine(),
		"inboundCount":                        s.inboundCount,
		"outboundCount":                       s.outboundCount,
		"dnsMainTransportTypes":               s.dnsTransports.main,
		"dnsFallbackTransportTypes":           s.dnsTransports.fallback,
		"dnsDefaultTransportTypes":            s.dnsTransports.defaults,
		"dnsProxyTransportTypes":              s.dnsTransports.proxyServer,
		"dnsDirectTransportTypes":             s.dnsTransports.direct,
		"dnsPolicyTransportTypes":             s.dnsTransports.policy,
		"outboundEndpointKinds":               s.outboundEndpointKinds,
		"connectionCount":                     connectionCount,
		"tcpConnectionAdmissionLimit":         admission.Limit,
		"tcpConnectionAdmissionActive":        admission.Active,
		"tcpConnectionAdmissionRejectedTotal": admission.Rejected,
		"running":                             s.running,
		"pauseCount":                          s.pauseCount.Load(),
		"wakeCount":                           s.wakeCount.Load(),
		"gcPercent":                           runtimeSetup.gcPercent,
		"logMaxLines":                         runtimeSetup.logMaxLines,
		"availableMemoryBytes":                memory.availableBytes,
		"physicalMemoryBytes":                 memory.physicalBytes,
		"goRuntimeResidentBytes":              memory.goResidentBytes,
		"nonGoPhysicalEstimateBytes":          memory.nonGoPhysicalEstimate,
		"goHeapAllocBytes":                    memory.heapAllocBytes,
		"goHeapInuseBytes":                    memory.heapInuseBytes,
		"goStackInuseBytes":                   memory.stackInuseBytes,
		"goGCCount":                           memory.gcCount,
		"goGCPauseTotalNanoseconds":           memory.gcPauseTotalNanoseconds,
		"processCPUTimeNanoseconds":           processCPUTimeNanoseconds(),
		"goMaxProcs":                          runtime.GOMAXPROCS(0),
		"memoryPressureEventCount":            memoryPressureEventCount.Load(),
		"physicalPathSupportsIPv4":            nat64.supportsIPv4,
		"physicalPathSupportsIPv6":            nat64.supportsIPv6,
		"nat64SynthesisAttempts":              nat64.attempts,
		"nat64SynthesisApplied":               nat64.applied,
		"nat64SynthesisFailures":              nat64.failures,
	}
	if runtimeSetup.softMemoryLimit > 0 {
		diagnostics["softMemoryLimit"] = runtimeSetup.softMemoryLimit
	}
	// Which stack the live tun actually runs, read from the same source upstream's own
	// /configs answers from (executor.GetGeneral -> listener.GetTunConf, executor.go:202) --
	// a readback of the listener's record, not an echo of what was sent. The three-stack
	// matrix on tvOS is the consumer. Absent when no tun is live, and the Enable guard is
	// load-bearing: LC.Tun's zero-value Stack is TunGvisor, so an unguarded read would
	// confidently name a stack that does not exist. Values are mihomo's own literals
	// (gVisor / System / Mixed), verbatim.
	if conf := coreListener.GetTunConf(); conf.Enable {
		diagnostics["tunStack"] = conf.Stack.String()
	}
	// The memory judge's last answer on a reload, in numbers (reload_memory_guard.go). Absent
	// until a reload has been judged, so "never asked" cannot read as "accepted". Read after
	// the fact by design: Reload holds s.mu for its whole transaction, and so does this, which
	// makes it useless as a liveness probe during a reload -- that reading belongs to the host.
	if s.reloadVerdict.Reason != "" {
		diagnostics["reloadVerdict"] = s.reloadVerdict
	}
	// The threshold machine's counters. In report-only mode these ARE the deliverable: how
	// often it would have shed, and how often it predicted rather than reacted.
	for key, value := range pressureThresholdDiagnostics() {
		diagnostics[key] = value
	}
	// Live gVisor TCP window state. The hook is mounted by the full-gVisor
	// stack's Start and cleared by its Close alone; Mixed builds a UDP-only
	// gVisor half without mounting it (its TCP rides the system half). So
	// nil means "no gVisor TCP path", not "no gVisor stack" -- presence
	// tells the gvisor stack apart from BOTH system and mixed, and stack
	// identity itself is the tunStack key above. The range is read back
	// from the stack itself so evidence can prove which window a run really
	// used; the distribution shows how far moderation actually grew busy
	// connections.
	if snapshot := tun.GVisorTCPWindowSnapshot; snapshot != nil {
		window := snapshot()
		diagnostics["gvisorTCPWindowMinBytes"] = window.MinBytes
		diagnostics["gvisorTCPWindowDefaultBytes"] = window.DefaultBytes
		diagnostics["gvisorTCPWindowMaxBytes"] = window.MaxBytes
		diagnostics["gvisorTCPWindowConnections"] = window.TCPConnections
		diagnostics["gvisorTCPReceiveOccupancyP50Bytes"] = window.ReceiveOccupancyP50Bytes
		diagnostics["gvisorTCPReceiveOccupancyP95Bytes"] = window.ReceiveOccupancyP95Bytes
		diagnostics["gvisorTCPReceiveOccupancyMaxBytes"] = window.ReceiveOccupancyMaxBytes
		diagnostics["gvisorTCPConnectionsNearReceiveMax"] = window.ConnectionsNearReceiveMax
		// The drop total is the counter to read for backpressure. NearReceiveMax above
		// compares payload against a memory-enforced cap and so reads 0 even at
		// saturation; this increments only when the gate actually refused a segment.
		diagnostics["gvisorTCPSegmentQueueDroppedTotal"] = window.SegmentQueueDroppedTotal
	}
	if updater, ok := s.ifaceListener.(*interfaceUpdater); ok {
		path := updater.snapshot()
		diagnostics["physicalPathUpdatesReceived"] = path.received
		diagnostics["physicalPathUpdatesApplied"] = path.applied
		diagnostics["physicalPathIdentityChanges"] = path.identityChanges
		diagnostics["physicalPathConnectionResets"] = path.connectionResets
	}
	if snapshot := tun.GVisorPacketIOSnapshot; snapshot != nil {
		packetIO := snapshot()
		diagnostics["corePacketIngressReadCalls"] = packetIO.IngressReadCalls
		diagnostics["corePacketIngressReadWouldBlock"] = packetIO.IngressReadWouldBlock
		diagnostics["corePacketIngressReadPackets"] = packetIO.IngressReadPackets
		diagnostics["corePacketIngressReadBytes"] = packetIO.IngressReadBytes
		diagnostics["corePacketIngressReadErrors"] = packetIO.IngressReadErrors
		diagnostics["corePacketIngressDispatchPackets"] = packetIO.IngressDispatchPackets
		diagnostics["corePacketIngressDispatchBytes"] = packetIO.IngressDispatchBytes
		diagnostics["corePacketProcessorQueueDepth"] = packetIO.ProcessorQueueDepth
		diagnostics["corePacketProcessorQueuePeak"] = packetIO.ProcessorQueuePeak
		diagnostics["corePacketEgressWriteCalls"] = packetIO.EgressWriteCalls
		diagnostics["corePacketEgressWritePackets"] = packetIO.EgressWritePackets
		diagnostics["corePacketEgressWriteBytes"] = packetIO.EgressWriteBytes
		diagnostics["corePacketEgressWriteErrors"] = packetIO.EgressWriteErrors
	}
	return bridgeSafeString(mustJSON(diagnostics))
}

// finalizeConfigForIOS produces the exact runtime configuration before any
// consumer (especially Swift OpenTun) observes it.
func finalizeConfigForIOS(cfg *config.Config, underNE bool) {
	finalizeConfigForApple(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func finalizeConfigForApple(cfg *config.Config, policy appleRuntimePolicy) {
	if policy.networkExtension && policy.packetTunnel {
		ensureTunEnabled(&cfg.General.Tun)
	}
	overrideForAppleConfig(cfg, policy)
	if policy.networkExtension {
		overrideForNetworkExtension(cfg)
	}
}

func tunConfigurationsEqual(left, right LC.Tun) bool {
	left = cloneTunSlices(left)
	right = cloneTunSlices(right)
	left.Sort()
	right.Sort()
	sortTunFieldsMissingFromUpstream(&left)
	sortTunFieldsMissingFromUpstream(&right)
	return left.Equal(right) &&
		slices.Equal(left.LoopbackAddress, right.LoopbackAddress) &&
		slices.Equal(left.ExcludeSrcPort, right.ExcludeSrcPort) &&
		slices.Equal(left.ExcludeSrcPortRange, right.ExcludeSrcPortRange) &&
		slices.Equal(left.ExcludeDstPort, right.ExcludeDstPort) &&
		slices.Equal(left.ExcludeDstPortRange, right.ExcludeDstPortRange)
}

// cloneTunSlices prevents comparison sorting from mutating the caller's live
// configuration. LC.Tun is otherwise a shallow copy whose slice backing arrays
// would still be shared with BoxService.liveTun and the parsed candidate.
func cloneTunSlices(tun LC.Tun) LC.Tun {
	tun.DNSHijack = slices.Clone(tun.DNSHijack)
	tun.Inet4Address = slices.Clone(tun.Inet4Address)
	tun.Inet6Address = slices.Clone(tun.Inet6Address)
	tun.LoopbackAddress = slices.Clone(tun.LoopbackAddress)
	tun.RouteAddress = slices.Clone(tun.RouteAddress)
	tun.RouteAddressSet = slices.Clone(tun.RouteAddressSet)
	tun.RouteExcludeAddress = slices.Clone(tun.RouteExcludeAddress)
	tun.RouteExcludeAddressSet = slices.Clone(tun.RouteExcludeAddressSet)
	tun.IncludeInterface = slices.Clone(tun.IncludeInterface)
	tun.ExcludeInterface = slices.Clone(tun.ExcludeInterface)
	tun.IncludeUID = slices.Clone(tun.IncludeUID)
	tun.IncludeUIDRange = slices.Clone(tun.IncludeUIDRange)
	tun.ExcludeUID = slices.Clone(tun.ExcludeUID)
	tun.ExcludeUIDRange = slices.Clone(tun.ExcludeUIDRange)
	tun.ExcludeSrcPort = slices.Clone(tun.ExcludeSrcPort)
	tun.ExcludeSrcPortRange = slices.Clone(tun.ExcludeSrcPortRange)
	tun.ExcludeDstPort = slices.Clone(tun.ExcludeDstPort)
	tun.ExcludeDstPortRange = slices.Clone(tun.ExcludeDstPortRange)
	tun.IncludeAndroidUser = slices.Clone(tun.IncludeAndroidUser)
	tun.IncludePackage = slices.Clone(tun.IncludePackage)
	tun.ExcludePackage = slices.Clone(tun.ExcludePackage)
	tun.IncludeMACAddress = slices.Clone(tun.IncludeMACAddress)
	tun.ExcludeMACAddress = slices.Clone(tun.ExcludeMACAddress)
	tun.Inet4RouteAddress = slices.Clone(tun.Inet4RouteAddress)
	tun.Inet6RouteAddress = slices.Clone(tun.Inet6RouteAddress)
	tun.Inet4RouteExcludeAddress = slices.Clone(tun.Inet4RouteExcludeAddress)
	tun.Inet6RouteExcludeAddress = slices.Clone(tun.Inet6RouteExcludeAddress)
	return tun
}

// Mihomo LC.Tun.Equal currently omits these five fields, and LC.Tun.Sort does
// not normalize them. Hako supplements both operations at its reload boundary
// rather than modifying the upstream package.
func sortTunFieldsMissingFromUpstream(tun *LC.Tun) {
	slices.SortFunc(tun.LoopbackAddress, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	slices.Sort(tun.ExcludeSrcPort)
	slices.Sort(tun.ExcludeSrcPortRange)
	slices.Sort(tun.ExcludeDstPort)
	slices.Sort(tun.ExcludeDstPortRange)
}

// Status reports the tunnel lifecycle state (tunnel.Status().String():
// "Suspended"/"Inner"/"Running").
func (s *BoxService) Status() string {
	return bridgeSafeString(tunnel.Status().String())
}

// Mode returns the current routing mode ("rule"/"global"/"direct").
func (s *BoxService) Mode() string {
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	return bridgeSafeString(tunnel.Mode().String())
}

// SetMode switches the routing mode; unknown values are rejected so a UI
// typo cannot silently fall back (tunnel.SetMode ignores unknowns).
func (s *BoxService) SetMode(mode string) error {
	m, ok := tunnel.ModeMapping[strings.ToLower(mode)]
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: unknown mode %q", mode))
	}
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	tunnel.SetMode(m)
	return nil
}

// Pause maps NEProvider.sleep().
//
// recorded that "mihomo exposes no suspend/pause manager to wire into", so the only
// action taken here was shrinking the footprint against jetsam. That premise was wrong:
// github.com/metacubex/sing/service/pause is already in this module's dependencies,
// byte-identical to the package sing-box uses, and was simply never wired up. sing-box's
// CommandServer.Pause calls DevicePause on it, which stops every periodic task registered
// through pause.RegisterTicker -- most importantly the health-check tickers, whose URL tests
// are a TCP connect plus a full TLS handshake per proxy, and on Apple one trustd XPC round
// trip per verification. An idle iPhone logged 17,568 of those over 6.7 hours.
//
// FreeOSMemory stays. It is not something sing-box does on pause, but it is not a constraint
// on behaviour either -- it releases pages and destroys no work -- decided it for
// the jetsam budget.
// endPauseTimeout is sing-box's value for the same timer (experimental/libbox/command_server.go
// arms time.AfterFunc(time.Minute, ...)).
const endPauseTimeout = time.Minute

// releasePauseOnClose undoes what Pause armed, so a service that is gone cannot go on acting
// on the process-wide pause manager.
//
// Two things were never released here, and "disconnect on sleep" delivers exactly the sequence
// that exposes both: the system calls sleep() (Pause), and moments later, while the device is
// still asleep, stopTunnel (Close).
//
//  1. The iOS backstop timer. armEndPauseTimer arms a one-minute time.AfterFunc(pause.DeviceWake)
//     so a wake that never arrives cannot strand the core paused. Close never stopped it, so it
//     went on running against a *BoxService that no longer existed and called the bare,
//     receiver-less pause.DeviceWake() up to a minute later regardless.
//  2. The pause itself. component/pause's manager is process-wide by construction (the device is
//     asleep or it is not), so a service closed while paused left it paused for whatever ran
//     next -- a reconnect inside that window inherited a manager it never asked to be in, and its
//     own health checks would not run until the stray timer above eventually fired.
//
// pauseCount > wakeCount is this service's own record of a Pause with no matching Wake, checked
// so Close only releases a pause THIS service made -- never a device-wide pause some other live
// service is still holding.
func (s *BoxService) releasePauseOnClose() {
	s.endPauseMu.Lock()
	if s.endPauseTimer != nil {
		s.endPauseTimer.Stop()
	}
	s.endPauseMu.Unlock()

	if s.pauseCount.Load() > s.wakeCount.Load() {
		pause.DeviceWake()
	}
}

func (s *BoxService) Pause() {
	s.pauseCount.Add(1)
	pause.DevicePause()
	s.armEndPauseTimer()
	debug.FreeOSMemory()
}

// armEndPauseTimer bounds how long a pause can last on iOS, and exists only there.
//
// This mirrors sing-box exactly: its CommandServer.Pause arms a one-minute timer to call
// DeviceWake, and only under C.IsIos; its Wake then calls DeviceWake only when NOT on iOS.
// The pair means an iOS pause always self-expires rather than depending on a wake callback
// arriving, and a further sleep before it fires resets the minute.
//
// The cost of following that split is real and accepted: if iOS does deliver wake() promptly,
// health checks still stay suspended for up to a minute afterwards. The benefit is that the
// core can never be stranded in a paused state by a wake callback that never comes, which is
// the failure this timer exists to prevent. The runtime profile is used rather than a build
// constant because it is what the adapter actually declares -- the same binary carries the
// macOS profiles.
func (s *BoxService) armEndPauseTimer() {
	if !currentRuntimeProfile().inheritsIOSPacketTunnelBehavior() {
		return
	}
	s.endPauseMu.Lock()
	defer s.endPauseMu.Unlock()
	if s.endPauseTimer == nil {
		s.endPauseTimer = time.AfterFunc(endPauseTimeout, pause.DeviceWake)
		return
	}
	s.endPauseTimer.Reset(endPauseTimeout)
}

// Wake maps NEProvider.wake(): DNS transports and cached resolver state may have
// died while the device slept, so drop those.
//
// It deliberately does NOT close tracked connections. That line was here and was
// never decided: chose resolver.ResetConnection() and nothing more, the
// teardown arrived later inside a commit whose one-line message does not mention it,
// and the comment then cited for it. iOS delivers sleep/wake pairs routinely,
// including momentary ones, so on every one of them every app's live session through
// the tunnel died and had to be re-established -- a TCP connect plus a full TLS
// handshake each, and one trustd XPC round trip per handshake on iOS.
//
// A sleep/wake pair is not evidence that a connection died. A changed physical path
// is, and that case is already handled by the path monitor, which closes tracked
// connections only on an interface identity or address-family change (see
// updateDefaultPath in monitor.go). Upstream sing-box converged on the same answer:
// an iOS-only debounce first, then removing the reset from sleep and wake entirely.
func (s *BoxService) Wake() {
	s.wakeCount.Add(1)
	// Every profile resumes here, iOS included. It used to skip iOS and leave the
	// transition to the one-minute timer armed by Pause, so the platform the
	// pausing was built for was the one where a delivered wake did nothing and the
	// next health check landed at sleep + 60s + a full interval.
	//
	// The reason on record was that sing-box's CommandServer splits it that way,
	// and the code conceded the call would be "harmless in isolation". does
	// not accept sing-box as an authority on what behaviour should be, and pausing
	// health checks is a Hako addition to begin with -- mihomo has no
	// component/pause and its ticker runs straight through a sleep. Apple documents
	// wake as delivered "immediately after the system wakes up" (NEProvider.h),
	// with no iOS exception.
	//
	// The timer stays as what it always was: a backstop for a wake that never
	// arrives, which would otherwise strand the core paused for the session.
	pause.DeviceWake()
	resolver.ResetConnection()
}
