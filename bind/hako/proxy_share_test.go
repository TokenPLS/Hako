package hako

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyShareLifecycleSurvivesReloadAndClosesWithService(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}

	port := reserveProxySharePort(t)
	const username = "hako-test-user"
	const password = "hako-test-password"
	if err := service.StartProxyShare(int32(port), username, password); err != nil {
		t.Fatalf("StartProxyShare: %v", err)
	}
	assertProxyShareStatus(t, service, true, port)
	assertProxyShareAuthentication(t, service, username, password)
	assertTCPListenerReachable(t, port, true)
	assertProxyShareHTTPAuthentication(t, port, username, password)
	assertProxyShareSOCKS5Authentication(t, port, username, password)

	if err := service.Reload(helloYAML); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	assertProxyShareStatus(t, service, true, port)
	assertProxyShareAuthentication(t, service, username, password)
	assertTCPListenerReachable(t, port, true)

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertProxyShareStatus(t, service, false, 0)
	assertTCPListenerReachable(t, port, false)
	if service.proxyShare != nil {
		t.Fatal("proxy-share runtime survived service Close")
	}
}

// A community subscription almost always carries a mixed-port. Upstream never
// refuses anything because a listener exists -- its sharing story IS the
// config's own port (allow-lan), and a genuine port collision is a logged bind
// error, warn-and-continue (listener/listener.go ReCreateMixed). Our old rule
// ("any config listener present -> share refused") was written when NE stripped
// every config listener, so it refused nobody; after returned the inbound
// surface to users it started refusing exactly the configs people actually
// import. Ruled 2026-08-15: drop the refusal, let bind report collisions.
func TestProxyShareCoexistsWithConfigMixedPort(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	configPort := reserveProxySharePort(t)
	document := strings.Replace(helloYAML, "mode: rule",
		"mixed-port: "+strconv.Itoa(configPort)+"\nmode: rule", 1)
	if err := service.Start(document); err != nil {
		t.Fatal(err)
	}

	sharePort := reserveProxySharePort(t)
	if err := service.StartProxyShare(int32(sharePort), "hako-test-user", "hako-test-password"); err != nil {
		t.Fatalf("StartProxyShare next to a config mixed-port: %v -- a community "+
			"subscription's standard shape permanently locked the feature", err)
	}
	assertProxyShareStatus(t, service, true, sharePort)
	assertTCPListenerReachable(t, sharePort, true)

	// Whether sharing on the config's own port collides is decided by the
	// platform, not by us: the config listener (allow-lan off) holds
	// 127.0.0.1:P while the share binds the wildcard, and macOS sanctions that
	// pair while iOS refuses it (measured on an iPad: share on 7899 -> 200,
	// share on the config's 7890 -> a genuine bind failure). This test runs on
	// the host, so it pins the refusal that is ours to keep either way -- an occupied wildcard
	// port must surface as the OS bind error, never as a policy sentence about
	// listeners. Do not restate the macOS half as a cross-platform fact; that
	// mistake nearly turned iOS's correct rejection into a regression hunt.
	if err := service.StopProxyShare(); err != nil {
		t.Fatal(err)
	}
	occupiedPort := reserveProxySharePort(t)
	occupant, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(occupiedPort)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupant.Close() })
	err = service.StartProxyShare(int32(occupiedPort), "hako-test-user", "hako-test-password")
	if err == nil {
		t.Fatal("sharing on an occupied wildcard port succeeded; the OS bind error was swallowed")
	}
	if strings.Contains(err.Error(), "conflicts with an existing local listener") {
		t.Fatalf("collision reported the removed policy refusal instead of the bind error: %v", err)
	}
}

func TestProxyShareRequiresBoundedCredentialsAndRunningService(t *testing.T) {
	service := &BoxService{platform: newRecordingPlatform()}
	for name, testCase := range map[string]struct {
		port     int32
		username string
		password string
	}{
		"not running":        {1082, "user", "long-enough-password"},
		"privileged port":    {1023, "user", "long-enough-password"},
		"empty username":     {1082, "", "long-enough-password"},
		"username has colon": {1082, "user:name", "long-enough-password"},
		"empty password":     {1082, "user", ""},
		"control character":  {1082, "user", "long-enough\npassword"},
	} {
		t.Run(name, func(t *testing.T) {
			service.running = name != "not running"
			if err := service.StartProxyShare(testCase.port, testCase.username, testCase.password); err == nil {
				t.Fatal("invalid proxy-share request unexpectedly succeeded")
			}
		})
	}
	service.running = false
}

func TestProxySharePasswordFloorFollowsProtocolNotStrengthPolicy(t *testing.T) {
	// The LAN proxy-share credential floor must match the wire protocol
	// (SOCKS5 RFC 1929 / HTTP Basic RFC 7617 accept a non-empty 1...255-byte
	// password) and upstream's verbatim authenticator, not an invented 12-byte
	// strength policy. Password strength is a non-blocking client-side hint.
	const validPort int32 = 1082
	const validUser = "user"

	for name, password := range map[string]string{
		"single byte":   "x",
		"six bytes":     "share1",
		"eleven bytes":  "elevenbytes",
		"max 255 bytes": strings.Repeat("a", int(ProxyShareMaximumCredentialBytes)),
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := newProxyShareConfiguration(validPort, validUser, password); err != nil {
				t.Fatalf("password %q (%d bytes) must be accepted: %v", password, len(password), err)
			}
		})
	}

	for name, password := range map[string]string{
		"empty":             "",
		"over 255 bytes":    strings.Repeat("a", int(ProxyShareMaximumCredentialBytes)+1),
		"control character": "abc\ndef",
	} {
		t.Run("rejected/"+name, func(t *testing.T) {
			if _, err := newProxyShareConfiguration(validPort, validUser, password); err == nil {
				t.Fatalf("password %q must be rejected", password)
			}
		})
	}
}

func TestClashAPIClientControlsProxyShareWithoutLeakingCredentials(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewClashAPIClientWithOptions(
		path,
		newRecordingClashAPIHandler(),
		&ClashAPIClientOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	port := reserveProxySharePort(t)
	const username = "private-user"
	const password = "private-password-value"
	if err := client.StartProxyShare(int32(port), username, password); err != nil {
		t.Fatalf("client StartProxyShare: %v", err)
	}
	status, err := client.GetProxyShareStatus()
	if err != nil {
		t.Fatalf("GetProxyShareStatus: %v", err)
	}
	if strings.Contains(status, username) || strings.Contains(status, password) {
		t.Fatalf("proxy-share status leaked credentials: %s", status)
	}
	assertProxyShareStatusJSON(t, status, true, port)
	const rejectedSecret = "do-not-leak"
	if _, err := client.request(http.MethodPut, "/hako/v1/proxy-share", proxyShareRequest{
		Port:     int32(port),
		Username: "private-user",
		// A control character keeps the request invalid post floor-change so the
		// rejection path is still exercised, and the error must not echo the secret.
		Password: rejectedSecret + "\n",
	}); err == nil || strings.Contains(err.Error(), rejectedSecret) {
		t.Fatalf("rejected proxy-share request leaked credentials: %v", err)
	}

	if err := client.StopProxyShare(); err != nil {
		t.Fatalf("client StopProxyShare: %v", err)
	}
	status, err = client.GetProxyShareStatus()
	if err != nil {
		t.Fatalf("GetProxyShareStatus after stop: %v", err)
	}
	assertProxyShareStatusJSON(t, status, false, 0)
}

// One 422 for every failure leaves the App with nothing to say. A user whose
// subscription carries mixed-port 7890 and who shares on 7890 gets a genuine
// bind failure -- on iOS, where the wildcard share and the config's loopback
// listener DO collide (macOS disagrees; see proxy_share.go) -- and the only
// remedy is "pick another port". The App could not tell them that, because
// "port unavailable" and "your password has a newline in it" arrived as the
// same sentence.
//
// Naming the unavailable port leaks nothing: the caller chose it, holds the
// App Group socket, and could learn the same thing by binding it. What must
// stay redacted is WHAT holds it, and every credential.
func TestProxyShareUnavailablePortIsDistinguishableFromOtherRejections(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewClashAPIClientWithOptions(path, newRecordingClashAPIHandler(), &ClashAPIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	occupiedPort := reserveProxySharePort(t)
	occupant, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(occupiedPort)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupant.Close() })

	_, portErr := client.request(http.MethodPut, "/hako/v1/proxy-share", proxyShareRequest{
		Port: int32(occupiedPort), Username: "private-user", Password: "private-password-value",
	})
	if portErr == nil {
		t.Fatal("sharing on an occupied port succeeded")
	}
	const secret = "do-not-leak"
	_, credentialErr := client.request(http.MethodPut, "/hako/v1/proxy-share", proxyShareRequest{
		Port: int32(reserveProxySharePort(t)), Username: "private-user", Password: secret + "\n",
	})
	if credentialErr == nil {
		t.Fatal("an invalid password was accepted")
	}

	if portErr.Error() == credentialErr.Error() {
		t.Fatalf("an occupied port and a malformed credential are the same error (%q); "+
			"the App cannot tell the user to pick another port", portErr)
	}
	if !strings.Contains(portErr.Error(), strconv.Itoa(occupiedPort)) {
		t.Fatalf("the port rejection does not name the port the caller asked for: %q", portErr)
	}
	// The redaction that must survive: what holds the port, and any credential.
	for _, forbidden := range []string{"listener", "127.0.0.1", "0.0.0.0", secret, "private-password-value"} {
		if strings.Contains(portErr.Error(), forbidden) {
			t.Fatalf("port rejection leaked %q: %s", forbidden, portErr)
		}
	}
	if strings.Contains(credentialErr.Error(), secret) {
		t.Fatalf("credential rejection leaked the secret: %s", credentialErr)
	}
}

func TestProxyShareRemoteFilterAllowsOnlyLocalScope(t *testing.T) {
	for address, allowed := range map[string]bool{
		"127.0.0.1":            true,
		"10.1.2.3":             true,
		"172.20.10.2":          true,
		"192.168.1.2":          true,
		"169.254.1.2":          true,
		"::1":                  true,
		"fd00::1":              true,
		"fe80::1":              true,
		"8.8.8.8":              false,
		"1.1.1.1":              false,
		"2001:4860:4860::8888": false,
	} {
		t.Run(address, func(t *testing.T) {
			remote := &net.TCPAddr{IP: net.ParseIP(address), Port: 12345}
			if got := proxyShareRemoteAllowed(remote); got != allowed {
				t.Fatalf("proxyShareRemoteAllowed(%s) = %v, want %v", address, got, allowed)
			}
		})
	}
}

func reserveProxySharePort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpListener.Addr().(*net.TCPAddr).Port
		udpListener, udpError := net.ListenUDP("udp4", &net.UDPAddr{
			IP: net.IPv4(127, 0, 0, 1), Port: port,
		})
		if udpListener != nil {
			_ = udpListener.Close()
		}
		if err := tcpListener.Close(); err != nil {
			t.Fatal(err)
		}
		if udpError == nil && port >= int(ProxyShareMinimumPort) {
			return port
		}
	}
	t.Fatal("unable to reserve an available TCP+UDP proxy-share port")
	return 0
}

func assertProxyShareStatus(t *testing.T, service *BoxService, enabled bool, port int) {
	t.Helper()
	assertProxyShareStatusJSON(t, service.ProxyShareStatusJSON(), enabled, port)
}

func assertProxyShareStatusJSON(t *testing.T, payload string, enabled bool, port int) {
	t.Helper()
	var status struct {
		Enabled                bool     `json:"enabled"`
		Port                   int      `json:"port"`
		Protocols              []string `json:"protocols"`
		AuthenticationRequired bool     `json:"authenticationRequired"`
	}
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode proxy-share status: %v (%q)", err, payload)
	}
	if status.Enabled != enabled || status.Port != port {
		t.Fatalf("proxy-share status = %+v, want enabled=%v port=%d", status, enabled, port)
	}
	if enabled {
		if !status.AuthenticationRequired || strings.Join(status.Protocols, ",") != "http,socks5" {
			t.Fatalf("enabled proxy-share contract = %+v", status)
		}
	} else if status.AuthenticationRequired || len(status.Protocols) != 0 {
		t.Fatalf("disabled proxy-share contract = %+v", status)
	}
}

func assertProxyShareAuthentication(t *testing.T, service *BoxService, username, password string) {
	t.Helper()
	if service.proxyShare == nil {
		t.Fatal("proxy-share runtime is missing")
	}
	authenticator := service.proxyShare.authentication.Authenticator()
	if authenticator == nil || !authenticator.Verify(username, password) {
		t.Fatal("proxy-share credentials were not installed")
	}
	if authenticator.Verify(username, password+"-wrong") {
		t.Fatal("proxy-share authenticator accepted a wrong password")
	}
}

func assertTCPListenerReachable(t *testing.T, port int, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
		if connection != nil {
			_ = connection.Close()
		}
		if (err == nil) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy-share listener reachable=%v, want %v: %v", err == nil, want, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertProxyShareHTTPAuthentication(t *testing.T, port int, username, password string) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	request := func(user *url.Userinfo) int {
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			User:   user,
		}
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   2 * time.Second,
		}
		response, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("HTTP proxy request: %v", err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := request(nil); status != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated HTTP proxy status = %d, want 407", status)
	}
	if status := request(url.UserPassword(username, password)); status != http.StatusNoContent {
		t.Fatalf("authenticated HTTP proxy status = %d, want 204", status)
	}
}

func assertProxyShareSOCKS5Authentication(t *testing.T, port int, username, password string) {
	t.Helper()
	dial := func() net.Conn {
		connection, err := net.DialTimeout(
			"tcp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			time.Second,
		)
		if err != nil {
			t.Fatalf("SOCKS5 dial: %v", err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		return connection
	}

	unauthenticated := dial()
	if _, err := unauthenticated.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(unauthenticated, selection); err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Close()
	if selection[0] != 5 || selection[1] == 0 {
		t.Fatalf("SOCKS5 accepted unauthenticated method selection: %v", selection)
	}

	authenticated := dial()
	defer authenticated.Close()
	if _, err := authenticated.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(authenticated, selection); err != nil {
		t.Fatal(err)
	}
	if selection[0] != 5 || selection[1] != 2 {
		t.Fatalf("SOCKS5 authenticated method selection = %v, want [5 2]", selection)
	}
	authRequest := append(
		[]byte{1, byte(len(username))},
		[]byte(username)...,
	)
	authRequest = append(authRequest, byte(len(password)))
	authRequest = append(authRequest, []byte(password)...)
	if _, err := authenticated.Write(authRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(authenticated, selection); err != nil {
		t.Fatal(err)
	}
	if selection[0] != 1 || selection[1] != 0 {
		t.Fatalf("SOCKS5 authentication response = %v, want [1 0]", selection)
	}
}
