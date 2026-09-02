package hako

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/sirupsen/logrus"
)

func testOptions(t *testing.T) *SetupOptions {
	t.Helper()
	base := t.TempDir()
	return &SetupOptions{
		BasePath:    base,
		WorkingPath: filepath.Join(base, "working"),
		TempPath:    filepath.Join(base, "temp"),
	}
}

func TestAppOnlySetupKeepsPreflightOffPersistentCache(t *testing.T) {
	if os.Getenv("HAKO_APP_ONLY_SETUP_HELPER") == "1" {
		opts := testOptions(t)
		opts.DisablePersistentCache = true
		if err := Setup(opts); err != nil {
			t.Fatal(err)
		}
		if err := CheckConfig(helloYAML); err != nil {
			t.Fatal(err)
		}
		// The App preflights final YAML before the candidate directory is
		// atomically renamed to its published revision path. Typed parsing must
		// validate the safe path without opening the provider; provider contents
		// were already consumed from the staging path by FinalizeForIOS.
		publishedProvider := filepath.Join(
			opts.WorkingPath,
			"store", "profiles", "11111111-1111-1111-1111-111111111111",
			"revisions", "22222222-2222-2222-2222-222222222222",
			"providers", "rules.yaml",
		)
		prePublishConfig := strings.Replace(
			helloYAML,
			"rules:\n  - MATCH,DIRECT\n",
			"rule-providers:\n  staged:\n    type: file\n    behavior: classical\n    path: "+publishedProvider+"\nrules:\n  - RULE-SET,staged,DIRECT\n",
			1,
		)
		if _, err := os.Stat(publishedProvider); !os.IsNotExist(err) {
			t.Fatalf("published provider unexpectedly exists before preflight: %v", err)
		}
		if err := CheckConfig(prePublishConfig); err != nil {
			t.Fatalf("preflight statted unpublished provider path: %v", err)
		}
		if _, err := os.Stat(filepath.Join(opts.WorkingPath, "cache.db")); !os.IsNotExist(err) {
			t.Fatalf("App preflight created persistent cache: %v", err)
		}
		if err := Setup(opts); err != nil {
			t.Fatalf("repeated App-only Setup: %v", err)
		}
		if _, err := NewService(newRecordingPlatform()); err == nil || !strings.Contains(err.Error(), "App-only") {
			t.Fatalf("NewService after App-only Setup error = %v", err)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAppOnlySetupKeepsPreflightOffPersistentCache$")
	command.Env = append(os.Environ(), "HAKO_APP_ONLY_SETUP_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func TestSetupCreatesAndProbesDirs(t *testing.T) {
	opts := testOptions(t)
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	for _, dir := range []string{
		opts.WorkingPath,
		opts.TempPath,
		filepath.Join(opts.WorkingPath, "providers"),
		filepath.Join(opts.WorkingPath, "geodata"),
	} {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			t.Fatalf("expected directory %s: %v", dir, err)
		}
	}
}

func TestSetupRejectsUnusablePath(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocked")
	if err := os.WriteFile(blocker, []byte("file, not dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Setup(&SetupOptions{
		BasePath:    base,
		WorkingPath: filepath.Join(blocker, "working"), // parent is a file
		TempPath:    filepath.Join(base, "temp"),
	})
	if err == nil {
		t.Fatal("Setup should fail when WorkingPath cannot be created")
	}
	if !strings0(err.Error(), "hako:") {
		t.Fatalf("error should be prefixed and readable, got: %v", err)
	}
}

func TestSetupRequiresBasePath(t *testing.T) {
	base := t.TempDir()
	err := Setup(&SetupOptions{
		WorkingPath: filepath.Join(base, "working"),
		TempPath:    filepath.Join(base, "temp"),
	})
	if err == nil || !strings0(err.Error(), "BasePath") {
		t.Fatalf("missing BasePath error = %v", err)
	}
}

func TestSetupSelectsValidatedTunMTU(t *testing.T) {
	t.Cleanup(func() {
		activeCoreCount.Store(0)
		setTunMTU(0)
	})

	opts := testOptions(t)
	opts.TunMTU = 1500
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup custom TunMTU: %v", err)
	}
	if got := TunMTU(); got != 1500 {
		t.Fatalf("TunMTU after Setup = %d, want 1500", got)
	}
	tun := &LC.Tun{Enable: true, MTU: 4064}
	overrideTunForIOS(tun)
	if got := tun.MTU; got != 1500 {
		t.Fatalf("Core tun MTU = %d, want setup-selected 1500", got)
	}
	if got := newTunOptions(tun).GetMTU(); got != 1500 {
		t.Fatalf("Apple TunOptions MTU = %d, want 1500", got)
	}
	activeCoreCount.Store(1)
	runningChange := testOptions(t)
	runningChange.TunMTU = 1280
	if err := Setup(runningChange); err == nil || !strings0(err.Error(), "requires restart") {
		t.Fatalf("running-core TunMTU change error = %v", err)
	}
	if got := TunMTU(); got != 1500 {
		t.Fatalf("running-core change altered effective MTU to %d", got)
	}
	activeCoreCount.Store(0)

	for _, invalid := range []int{-1, 1, 1279, 9001, 1<<32 + 1500} {
		bad := testOptions(t)
		bad.TunMTU = invalid
		if err := Setup(bad); err == nil || !strings0(err.Error(), "TunMTU") {
			t.Fatalf("Setup TunMTU=%d error = %v", invalid, err)
		}
		if got := TunMTU(); got != 1500 {
			t.Fatalf("invalid Setup changed effective MTU to %d", got)
		}
	}

	defaults := testOptions(t)
	if err := Setup(defaults); err != nil {
		t.Fatalf("Setup default TunMTU: %v", err)
	}
	if got := TunMTU(); got != defaultTunMTU {
		t.Fatalf("zero TunMTU = %d, want default %d", got, defaultTunMTU)
	}
}

// strings0 avoids importing strings just for Contains in this test file.
func strings0(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The bbolt DoD ("HomeDir wired first => cache.db opens inside the
// sandbox path") is asserted inside TestStartNoTunReachesRunning:
// cachefile.Cache() is a process-wide sync.Once, so the one place that may
// claim it is the first real core start.

// DoD: Setup applies the memory trio when a budget is given, and
// the iOS-tagged build reports the low-memory recipe.
func TestSetupAppliesMemoryTrio(t *testing.T) {
	origGC := debug.SetGCPercent(100) // read current, will restore
	t.Cleanup(func() { debug.SetGCPercent(origGC) })

	opts := testOptions(t)
	opts.MemoryLimit = 50 * 1024 * 1024
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// SetGCPercent returns the previous value; after Setup it should be 10.
	if prev := debug.SetGCPercent(10); prev != 10 {
		t.Fatalf("GCPercent after Setup = %d, want 10", prev)
	}
	// with_low_memory is build-tag specific (iOS slice yes, macOS no); asserted in the tagged low_memory_test.go.
}

func TestEffectiveMaxProcs(t *testing.T) {
	ncpu := runtime.NumCPU()
	cases := []struct {
		name        string
		maxProcs    int
		memoryLimit int64
		want        int
	}{
		{"unconstrained leaves default", 0, 0, 0},
		{"constrained caps at 4", 0, 1 << 20, min(4, ncpu)},
		{"explicit honored", 2, 1 << 20, min(2, ncpu)},
		{"explicit clamped to NumCPU", 999, 0, ncpu},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := effectiveMaxProcs(&SetupOptions{MaxProcs: c.maxProcs, MemoryLimit: c.memoryLimit})
			if got != c.want {
				t.Fatalf("effectiveMaxProcs = %d, want %d", got, c.want)
			}
		})
	}
}

func TestTimeZoneShim(t *testing.T) {
	systemLocal := time.Local
	opts := testOptions(t)
	opts.TimeZone = "Asia/Tokyo"
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := hakoLocalTime(time.Now()).Format("-07:00"); got != "+09:00" {
		t.Fatalf("Hako local offset = %s, want +09:00", got)
	}
	if probe := TZProbe(); !strings.Contains(probe, "loc=Asia/Tokyo") || !strings.Contains(probe, "offset=+09:00") {
		t.Fatalf("TZProbe = %q", probe)
	}
	if time.Local != systemLocal {
		t.Fatal("Setup must not mutate race-unsafe time.Local")
	}

	opts.TimeZone = "Not/AZone"
	if err := Setup(opts); err == nil {
		t.Fatal("Setup should reject an unknown timezone id")
	}

	opts.TimeZone = "UTC"
	if err := Setup(opts); err == nil || !strings.Contains(err.Error(), "requires process restart") {
		t.Fatalf("Setup timezone change = %v", err)
	}
}

func TestLocalLogFormatterUsesHakoLocation(t *testing.T) {
	if err := applyTimeZone("Asia/Tokyo"); err != nil {
		t.Fatal(err)
	}
	formatter := &localLogFormatter{delegate: &logrus.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: "15:04 -07:00",
	}}
	formatted, err := formatter.Format(&logrus.Entry{
		Logger:  logrus.New(),
		Time:    time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
		Level:   logrus.InfoLevel,
		Message: "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(formatted); !strings.Contains(got, "09:00 +09:00") {
		t.Fatalf("localized log = %q", got)
	}
}

type recordingPlatform struct {
	lines                 chan string
	underNetworkExtension bool
	useAutoDetect         bool
	startMonitorErr       error
	monitorStarts         int
	monitorCloses         int
}

func (p *recordingPlatform) WriteLog(message string)                     { p.lines <- message }
func (p *recordingPlatform) OpenTun(TunOptions) (int32, error)           { return -1, errNotImplemented }
func (p *recordingPlatform) UsePlatformAutoDetectInterfaceControl() bool { return p.useAutoDetect }
func (p *recordingPlatform) AutoDetectInterfaceControl(int32) error      { return nil }
func (p *recordingPlatform) StartDefaultInterfaceMonitor(InterfaceUpdateListener) error {
	p.monitorStarts++
	return p.startMonitorErr
}
func (p *recordingPlatform) CloseDefaultInterfaceMonitor(InterfaceUpdateListener) error {
	p.monitorCloses++
	return nil
}
func (p *recordingPlatform) GetInterfaces() (NetworkInterfaceIterator, error) {
	return newNetworkInterfaceIterator(nil), nil
}
func (p *recordingPlatform) UnderNetworkExtension() bool { return p.underNetworkExtension }

func newRecordingPlatform() *recordingPlatform {
	return &recordingPlatform{lines: make(chan string, 256)}
}

func TestNewServiceRedirectsLogrusToWriteLog(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc == nil {
		t.Fatal("nil service")
	}

	logrus.Warnln("hako-log-redirect-probe")
	// NewService arms monitors whose own lines can arrive first; only the
	// probe's presence is this test's subject.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-platform.lines:
			if strings0(line, "hako-log-redirect-probe") {
				return
			}
		case <-deadline:
			t.Fatal("WriteLog never received the logrus line")
		}
	}
}

func TestNewServiceRequiresSetup(t *testing.T) {
	setupMu.Lock()
	setupDone = false
	setupMu.Unlock()
	if _, err := NewService(newRecordingPlatform()); err == nil {
		t.Fatal("NewService must fail before Setup")
	}
}
