package hako

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	C "github.com/TokenPLS/Hako/constant"
	coreListener "github.com/TokenPLS/Hako/listener"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/sirupsen/logrus"
)

func TestStartFailsClosedBeforeCoreWhenInterfaceMonitorCannotStart(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	platform := newRecordingPlatform()
	platform.useAutoDetect = true
	platform.startMonitorErr = errors.New("path monitor unavailable")
	svc, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	err = svc.Start(helloYAML)
	if err == nil || !strings.Contains(err.Error(), "start default interface monitor") {
		t.Fatalf("Start error = %v, want fail-closed monitor error", err)
	}
	if platform.monitorStarts != 1 || platform.monitorCloses != 1 {
		t.Fatalf("monitor start/close = %d/%d, want 1/1", platform.monitorStarts, platform.monitorCloses)
	}
	if svc.running || svc.ifaceListener != nil {
		t.Fatalf("failed Start retained state: running=%v listener=%v", svc.running, svc.ifaceListener)
	}
	if got := activeCoreCount.Load(); got != 0 {
		t.Fatalf("failed Start retained startup-invariant claim: %d", got)
	}
}

func TestRuntimeDiagnosticsLifecycle(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		var value map[string]any
		if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := read()
	if before["running"] != false || before["startTimeUnix"].(float64) != 0 {
		t.Fatalf("before Start = %#v", before)
	}
	if err := svc.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	if got := activeCoreCount.Load(); got != 1 {
		t.Fatalf("active core count after Start = %d, want 1", got)
	}
	afterStart := read()
	if afterStart["running"] != true || afterStart["startTimeUnix"].(float64) <= 0 {
		t.Fatalf("after Start = %#v", afterStart)
	}
	if afterStart["goroutines"].(float64) <= 0 || afterStart["outboundCount"].(float64) <= 0 {
		t.Fatalf("diagnostic counts = %#v", afterStart)
	}
	if got := afterStart["dnsMainTransportTypes"]; !reflect.DeepEqual(got, []any{"udp"}) {
		t.Fatalf("DNS main transports = %#v, want [udp]", got)
	}
	for _, key := range []string{
		"availableMemoryBytes",
		"goMaxProcs",
		"memoryPressureEventCount",
		"physicalMemoryBytes",
		"goRuntimeResidentBytes",
		"nonGoPhysicalEstimateBytes",
		"goHeapAllocBytes",
		"goHeapInuseBytes",
		"goStackInuseBytes",
		"goGCCount",
		"goGCPauseTotalNanoseconds",
		"processCPUTimeNanoseconds",
		"tcpConnectionAdmissionLimit",
		"tcpConnectionAdmissionActive",
		"tcpConnectionAdmissionRejectedTotal",
	} {
		if _, exists := afterStart[key]; !exists {
			t.Fatalf("runtime diagnostics missing %s: %#v", key, afterStart)
		}
	}
	if afterStart["goRuntimeResidentBytes"].(float64) <= 0 ||
		afterStart["goHeapInuseBytes"].(float64) <= 0 ||
		afterStart["goStackInuseBytes"].(float64) <= 0 {
		t.Fatalf("runtime memory diagnostics = %#v", afterStart)
	}
	if available := afterStart["availableMemoryBytes"].(float64); available < -1 {
		t.Fatalf("invalid available memory %v", available)
	}
	if maxProcs := afterStart["goMaxProcs"].(float64); maxProcs <= 0 {
		t.Fatalf("invalid GOMAXPROCS %v", maxProcs)
	}
	if pressureEvents := afterStart["memoryPressureEventCount"].(float64); pressureEvents < 0 {
		t.Fatalf("invalid memory pressure event count %v", pressureEvents)
	}
	if active := afterStart["tcpConnectionAdmissionActive"].(float64); active < 0 {
		t.Fatalf("invalid active TCP admission count %v", active)
	}
	if rejected := afterStart["tcpConnectionAdmissionRejectedTotal"].(float64); rejected < 0 {
		t.Fatalf("invalid rejected TCP admission count %v", rejected)
	}
	if physical := afterStart["physicalMemoryBytes"].(float64); physical >= 0 {
		nonGo := afterStart["nonGoPhysicalEstimateBytes"].(float64)
		if nonGo < 0 || nonGo > physical {
			t.Fatalf("non-Go estimate %v outside physical footprint %v", nonGo, physical)
		}
	}
	if cpu := afterStart["processCPUTimeNanoseconds"].(float64); cpu < -1 {
		t.Fatalf("invalid process CPU time %v", cpu)
	}
	if afterStart["pauseCount"].(float64) != 0 || afterStart["wakeCount"].(float64) != 0 {
		t.Fatalf("initial pause/wake counts = %#v", afterStart)
	}
	svc.Pause()
	svc.Wake()
	afterLifecycle := read()
	if afterLifecycle["pauseCount"].(float64) != 1 || afterLifecycle["wakeCount"].(float64) != 1 {
		t.Fatalf("pause/wake counts = %#v", afterLifecycle)
	}
	startTime := afterStart["startTimeUnix"]
	if err := svc.Reload(helloYAML); err != nil {
		t.Fatal(err)
	}
	if got := read()["startTimeUnix"]; got != startTime {
		t.Fatalf("reload changed start time: before=%v after=%v", startTime, got)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if got := activeCoreCount.Load(); got != 0 {
		t.Fatalf("active core count after Close = %d, want 0", got)
	}
	afterClose := read()
	if afterClose["running"] != false || afterClose["startTimeUnix"].(float64) != 0 {
		t.Fatalf("after Close = %#v", afterClose)
	}
}

// helloYAML is a minimal no-tun config: proxies + DNS, no tun stanza,
// no providers (nothing fetches the network at parse time).
const helloYAML = `
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
rules:
  - MATCH,DIRECT
`

// DoD: a proxies+DNS YAML without tun brings the core to Running,
// with logs flowing through platform.WriteLog.
func TestStartNoTunReachesRunning(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	opts := testOptions(t)
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := tunnel.Status(); got != tunnel.Running {
		t.Fatalf("tunnel.Status() = %v, want Running", got)
	}
	if err := svc.Start(helloYAML); err == nil {
		t.Fatal("second Start must be rejected (one process, one core)")
	}

	// (The bbolt "cache.db lands in WorkingPath" DoD is order-dependent in a
	// single-process test run — cachefile.Cache() is a package-wide
	// sync.Once, so whichever core-starting test runs first claims the path.
	// It is verified end-to-end on device instead: the NE created cache.db
	// inside the App Group container.)

	// The core logged during ApplyConfig; those lines must have reached
	// the platform, not stdout.
	select {
	case <-platform.lines:
	case <-time.After(2 * time.Second):
		t.Fatal("no core log line reached platform.WriteLog during Start")
	}
}

// DoD: Close is clean and the same process can start a fresh core
// afterwards — the full hello-core cycle twenty times over.
func TestCloseThenRestart(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	for cycle := 1; cycle <= 20; cycle++ {
		if err := svc.Start(helloYAML); err != nil {
			t.Fatalf("cycle %d Start: %v", cycle, err)
		}
		if got := tunnel.Status(); got != tunnel.Running {
			t.Fatalf("cycle %d status = %v, want Running", cycle, got)
		}
		if err := svc.Close(); err != nil {
			t.Fatalf("cycle %d Close: %v", cycle, err)
		}
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

// DoD: mode switching takes effect; Pause/Wake don't disturb a
// running core.
func TestModeStatusPauseWake(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if got := svc.Status(); got != tunnel.Running.String() {
		t.Fatalf("Status() = %q, want %q", got, tunnel.Running.String())
	}
	if err := svc.SetMode("Global"); err != nil { // case-insensitive
		t.Fatalf("SetMode(global): %v", err)
	}
	if svc.Mode() != tunnel.Global.String() {
		t.Fatalf("Mode() = %q after SetMode(global)", svc.Mode())
	}
	if err := svc.SetMode("bogus"); err == nil {
		t.Fatal("SetMode must reject unknown modes")
	}
	if err := svc.SetMode("rule"); err != nil {
		t.Fatalf("SetMode(rule): %v", err)
	}

	svc.Pause()
	svc.Wake()
	if got := svc.Status(); got != tunnel.Running.String() {
		t.Fatalf("Status() after Pause/Wake = %q, want Running", got)
	}
}

// DoD: Reload applies a new config on a running (no-tun) core
// without error and stays Running; rejects broken YAML.
func TestReloadNoTun(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := svc.Reload("mode: [broken"); err == nil {
		t.Fatal("Reload must reject unparsable YAML")
	}
	// Reload before Start on a fresh service is rejected.
	fresh, _ := NewService(newRecordingPlatform())
	if err := fresh.Reload(helloYAML); err == nil {
		t.Fatal("Reload before Start must fail")
	}

	globalYAML := helloYAML + "\n"
	if err := svc.Reload(globalYAML); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if tunnel.Status() != tunnel.Running {
		t.Fatalf("status after reload = %v, want Running", tunnel.Status())
	}
}

func TestStartRejectsBrokenYAML(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	err = svc.Start("mode: [broken")
	if err == nil {
		t.Fatal("Start must fail on unparsable YAML")
	}
	if !strings0(err.Error(), "parse config") {
		t.Fatalf("error should point at parsing, got: %v", err)
	}
	if svc.running {
		t.Fatal("failed Start must not mark the service running")
	}
}

// tunStack answers the three-stack matrix's readback requirement: which stack the live tun
// actually runs, read from the same source upstream's own /configs answers from
// (listener.GetTunConf), not inferred from what was sent. Absent when no tun is live -- and
// absence is load-bearing, because LC.Tun's zero-value Stack is TunGvisor: without the Enable
// guard a coreless run would confidently report a stack it does not have.
func TestRuntimeDiagnosticsCarryTheLiveTunStack(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var withoutTun map[string]any
	if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &withoutTun); err != nil {
		t.Fatal(err)
	}
	if value, present := withoutTun["tunStack"]; present {
		t.Fatalf("no tun is live, but diagnostics carry tunStack=%v (the zero-value lie)", value)
	}

	// The listener's own record, the way a real tun leaves it (listener.go writes LastTunConf
	// when it builds the device and clears it on cleanup). Each mihomo stack name must come
	// back verbatim -- the UI vocabulary rule pins the literal spellings.
	previous := coreListener.LastTunConf
	t.Cleanup(func() { coreListener.LastTunConf = previous })
	for stack, literal := range map[C.TUNStack]string{
		C.TunGvisor: "gVisor",
		C.TunSystem: "System",
		C.TunMixed:  "Mixed",
	} {
		coreListener.LastTunConf = LC.Tun{Enable: true, Stack: stack}
		var diagnostics map[string]any
		if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
			t.Fatal(err)
		}
		if diagnostics["tunStack"] != literal {
			t.Fatalf("tunStack = %v, want %q read back from the listener's live record", diagnostics["tunStack"], literal)
		}
	}
}
