package cachefile

import (
	"os"
	"os/exec"
	"testing"

	C "github.com/TokenPLS/Hako/constant"
)

func TestDisablePersistentCacheBeforeInitialization(t *testing.T) {
	if err := DisablePersistentCache(); err != nil {
		t.Fatal(err)
	}
	cache := Cache()
	if cache == nil {
		t.Fatal("Cache returned nil")
	}
	if cache.DB != nil {
		t.Fatal("disabled cache opened a persistent database")
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("nil-backed Close: %v", err)
	}
	if err := DisablePersistentCache(); err != nil {
		t.Fatalf("repeated disable is not idempotent: %v", err)
	}
}

func TestRejectDisableAfterPersistentInitialization(t *testing.T) {
	if os.Getenv("HAKO_CACHEFILE_LATE_DISABLE_HELPER") == "1" {
		C.SetHomeDir(t.TempDir())
		cache := Cache()
		if cache == nil || cache.DB == nil {
			t.Fatal("persistent cache did not open")
		}
		defer cache.Close()
		if err := DisablePersistentCache(); err == nil {
			t.Fatal("late disable succeeded")
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRejectDisableAfterPersistentInitialization$")
	command.Env = append(os.Environ(), "HAKO_CACHEFILE_LATE_DISABLE_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}
