package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

// setRuntimeSetupSoftMemoryLimitForTest puts the process in the state a platform ruling
// produces: with a ceiling, or -- as iOS runs -- without one.
func setRuntimeSetupSoftMemoryLimitForTest(t *testing.T, limit int64) {
	t.Helper()
	setupMu.Lock()
	previous := currentRuntimeSetup.softMemoryLimit
	currentRuntimeSetup.softMemoryLimit = limit
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		currentRuntimeSetup.softMemoryLimit = previous
		setupMu.Unlock()
	})
}

// A budget of zero is not a budget of zero. It is the absence of one.
//
// iOS carries no ceiling of ours by ruling: the 50 MiB this project used to set was its
// own invention, the 40 MiB later measured is not the number either, and the real limit
// is computed by the system per device and per moment. So SetupOptions.MemoryLimit is
// left unset, the branch that derives a soft limit never runs, and softMemoryLimit stays
// at its zero value.
//
// That zero then went out to the client on every record, in a field named budgetBytes,
// where it reads as a measured quantity rather than as "we do not have one". Any
// arithmetic on it is confidently wrong in the worst direction: footprint >= budget*0.8
// with budget zero is true for every footprint, so a crash at three megabytes would be
// reported to the reader as running out of memory, and they would be sent to delete a
// configuration that was never the problem. The one guard standing between that and the
// reader is a `budgetBytes > 0` test on the client, in a file whose own comments record
// three earlier versions of this branch being wrong.
//
// A ruling about the product is not allowed to make the code state something false. The
// wire form of "no ceiling" is an absent field, which cannot be multiplied.

func TestNoBudgetIsAbsentFromTheRecordRatherThanZero(t *testing.T) {
	home := breadcrumbHome(t)
	// A tunnel with no ceiling of ours: exactly what iOS runs.
	setRuntimeSetupSoftMemoryLimitForTest(t, 0)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("apply:profile")

	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("no record to read")
	}
	if strings.Contains(explanation, "budgetBytes") {
		t.Fatalf("a record with no budget still shipped a budgetBytes field, which reads as a measured ceiling: %s", explanation)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(explanation), &decoded); err != nil {
		t.Fatalf("explanation is not JSON: %v", err)
	}
	if _, present := decoded["budgetBytes"]; present {
		t.Fatal("budgetBytes is present, so a client can still do arithmetic with it")
	}
	// The footprint is the body of the account and must survive: what the tunnel was
	// using is a fact even when nothing says what it was allowed to use.
	if _, present := decoded["footprintBytes"]; !present {
		t.Fatal("dropping the budget also dropped the footprint, which is the half that is real")
	}
	_ = home
}

// When a budget genuinely exists -- an internal build sets one through
// ReloadSetupOptions -- it must still travel, or the field would be useless.
func TestARealBudgetStillTravels(t *testing.T) {
	breadcrumbHome(t)
	setRuntimeSetupSoftMemoryLimitForTest(t, 37<<20)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("apply:profile")

	explanation := ExplainLastStartup()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(explanation), &decoded); err != nil {
		t.Fatalf("explanation is not JSON: %v", err)
	}
	budget, present := decoded["budgetBytes"]
	if !present {
		t.Fatal("a record written under a real soft limit carried no budget")
	}
	if budget.(float64) != float64(37<<20) {
		t.Fatalf("budget travelled as %v, not the limit that was set", budget)
	}
}
