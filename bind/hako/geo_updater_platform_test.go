package hako

import (
	"net/http"
	"testing"
	"time"
)

// The geo updater routes are the first capability this product deliberately implements on one
// Apple platform and not the other, which the product rule allows in so many words: implement
// everything upstream offers, and where iOS cannot, macOS alone is an acceptable outcome.
//
// Both sides are measured rather than assumed. iOS: killed at 49.5 MiB, and GeoIP.dat is 17 MB
// to fetch and unpack. macOS: an app extension living steadily at 62.4 MiB with no limit set,
// reported by the consuming lane from a real first run. The macOS figure does not prove the
// download fits -- it proves the iOS ceiling is not what bounds it there.
func TestGeoUpdaterRoutesFollowThePlatformThatCanAffordThem(t *testing.T) {
	for _, testCase := range []struct {
		profile runtimeProfile
		open    bool
		why     string
	}{
		{runtimeProfileIOSPacketTunnel, false, "17 MB fetched and unpacked inside an extension measured dying at 49.5 MiB"},
		{runtimeProfileMacOSPacketTunnel, true, "a macOS app extension was measured living at 62.4 MiB with no limit configured"},
		{runtimeProfileMacOSApplication, true, "the containing app has no extension budget at all"},
	} {
		t.Run(testCase.profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, testCase.profile)

			port := freeLoopbackPort(t)
			addr := "127.0.0.1:" + port
			path := shortClashSocketPath(t)
			cfg := controllerConfig(t, addr)
			if err := startControlPlane(cfg, path); err != nil {
				t.Fatalf("startControlPlane: %v", err)
			}
			t.Cleanup(func() { stopClashAPI(path) })

			client := &http.Client{Timeout: 3 * time.Second}
			// GET on a POST-only path: 405 means registered, 404 means not. Asked this way so the
			// test never triggers a 17 MB download to find out whether it could.
			for _, route := range []string{"/configs/geo", "/upgrade/geo"} {
				response, err := client.Get("http://" + addr + route)
				if err != nil {
					t.Fatalf("GET %s: %v", route, err)
				}
				_ = response.Body.Close()
				registered := response.StatusCode == http.StatusMethodNotAllowed
				if registered != testCase.open {
					t.Errorf("%s registered=%v on %s, want %v: %s",
						route, registered, testCase.profile, testCase.open, testCase.why)
				}
			}

			// Positive control: the controller is really serving, so a 404 above cannot come from
			// a listener that never started.
			response, err := client.Get("http://" + addr + "/configs")
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("GET /configs = %v/%v; nothing above was measured", err, response)
			}
			_ = response.Body.Close()
		})
	}
}
