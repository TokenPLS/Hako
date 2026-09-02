package hako

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/tunnel/statistic"
)

type recordingSTUNHandler struct {
	progress chan *STUNTestProgress
	result   chan *STUNTestResult
	errors   chan string
}

type closeFromSTUNCallbackHandler struct {
	session chan *STUNTestSession
	closed  chan struct{}
}

func (h *closeFromSTUNCallbackHandler) OnProgress(*STUNTestProgress) {
	_ = (<-h.session).Close()
	close(h.closed)
}

func (*closeFromSTUNCallbackHandler) OnResult(*STUNTestResult) {}

func (*closeFromSTUNCallbackHandler) OnError(string) {}

func newRecordingSTUNHandler() *recordingSTUNHandler {
	return &recordingSTUNHandler{
		progress: make(chan *STUNTestProgress, 8),
		result:   make(chan *STUNTestResult, 1),
		errors:   make(chan string, 1),
	}
}

func (h *recordingSTUNHandler) OnProgress(progress *STUNTestProgress) {
	h.progress <- progress
}

func (h *recordingSTUNHandler) OnResult(result *STUNTestResult) {
	h.result <- result
}

func (h *recordingSTUNHandler) OnError(message string) {
	h.errors <- message
}

func TestSTUNConstantsAndFormatting(t *testing.T) {
	if STUNDefaultServer != "stun.voipgate.com:3478" {
		t.Fatalf("default server = %q", STUNDefaultServer)
	}
	if STUNPhaseBinding != 0 || STUNPhaseNATMapping != 1 || STUNPhaseNATFiltering != 2 || STUNPhaseDone != 3 {
		t.Fatal("unexpected STUN phase constants")
	}
	if FormatSTUNAddressFamily(STUNAddressFamilyIPv4) != "IPv4" || FormatSTUNAddressFamily(STUNAddressFamilyIPv6) != "IPv6" {
		t.Fatal("unexpected address-family formatting")
	}
	if FormatNATMapping(NATMappingEndpointIndependent) != "Endpoint Independent" {
		t.Fatal("unexpected NAT mapping formatting")
	}
	if FormatNATFiltering(NATFilteringAddressAndPortDependent) != "Address and Port Dependent" {
		t.Fatal("unexpected NAT filtering formatting")
	}
}

func TestClashAPIClientSTUNSessionUsesCoreOutboundAndTraffic(t *testing.T) {
	service, client := startSTUNTestCore(t)
	server, endpoint := startLocalSTUNServer(t, true)
	defer server.Close()

	uploadBefore, downloadBefore := statisticTotals()
	handler := newRecordingSTUNHandler()
	session, err := client.StartSTUNTest(endpoint, "DIRECT", handler)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	select {
	case progress := <-handler.progress:
		if progress.Phase != STUNPhaseBinding {
			t.Fatalf("initial phase = %d", progress.Phase)
		}
	case <-time.After(time.Second):
		t.Fatal("initial STUN progress missing")
	}
	select {
	case result := <-handler.result:
		if result.ExternalAddr != "198.51.100.20:4567" || result.ExternalAddressFamily != STUNAddressFamilyIPv4 {
			t.Fatalf("result = %+v", result)
		}
		if result.NATTypeSupported {
			t.Fatal("local fixture unexpectedly supports RFC 5780")
		}
	case message := <-handler.errors:
		t.Fatalf("STUN error: %s", message)
	case <-time.After(2 * time.Second):
		t.Fatal("STUN result missing")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	uploadAfter, downloadAfter := statisticTotals()
	if uploadAfter <= uploadBefore || downloadAfter <= downloadBefore {
		t.Fatalf("native traffic totals before=%d/%d after=%d/%d", uploadBefore, downloadBefore, uploadAfter, downloadAfter)
	}
	service.stunMu.Lock()
	active := len(service.stunSessions)
	service.stunMu.Unlock()
	if active != 0 {
		t.Fatalf("active STUN sessions = %d", active)
	}
}

func TestClashAPIClientSTUNCancellationAndReload(t *testing.T) {
	service, client := startSTUNTestCore(t)
	server, endpoint := startLocalSTUNServer(t, false)
	defer server.Close()
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	endpoint = net.JoinHostPort("localhost", port)
	handler := newRecordingSTUNHandler()
	session, err := client.StartSTUNTest(endpoint, "", handler)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.progress:
	case <-time.After(time.Second):
		t.Fatal("initial STUN progress missing")
	}
	foundDomainMetadata := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if tracker.Info().Metadata.Host == "localhost" {
			foundDomainMetadata = true
			return false
		}
		return true
	})
	if !foundDomainMetadata {
		t.Fatal("Follow Rules STUN dial discarded the server hostname")
	}
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- service.Reload(helloYAML) }()
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reload did not cancel and drain STUN session")
	}
	select {
	case message := <-handler.errors:
		if !strings.Contains(message, "cancel") {
			t.Fatalf("cancellation message = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation callback missing")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSTUNSessionMayCloseFromCallback(t *testing.T) {
	_, client := startSTUNTestCore(t)
	server, endpoint := startLocalSTUNServer(t, false)
	defer server.Close()
	handler := &closeFromSTUNCallbackHandler{
		session: make(chan *STUNTestSession, 1),
		closed:  make(chan struct{}),
	}
	session, err := client.StartSTUNTest(endpoint, "DIRECT", handler)
	if err != nil {
		t.Fatal(err)
	}
	handler.session <- session
	select {
	case <-handler.closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked inside STUN callback")
	}
}

func TestClashAPIClientSTUNRejectsUnknownAndConcurrentOutbound(t *testing.T) {
	_, client := startSTUNTestCore(t)
	server, endpoint := startLocalSTUNServer(t, false)
	defer server.Close()

	firstHandler := newRecordingSTUNHandler()
	first, err := client.StartSTUNTest(endpoint, "DIRECT", firstHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-firstHandler.progress:
	case <-time.After(time.Second):
		t.Fatal("first STUN progress missing")
	}

	busyHandler := newRecordingSTUNHandler()
	busy, err := client.StartSTUNTest(endpoint, "DIRECT", busyHandler)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-busyHandler.errors:
		if !strings.Contains(message, "already running") {
			t.Fatalf("busy error = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent STUN rejection missing")
	}
	_ = busy.Close()
	_ = first.Close()

	unknownHandler := newRecordingSTUNHandler()
	unknown, err := client.StartSTUNTest(endpoint, "missing-outbound", unknownHandler)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-unknownHandler.errors:
		if !strings.Contains(message, "not found") || strings.Contains(message, "missing-outbound") {
			t.Fatalf("unknown outbound error = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("unknown outbound rejection missing")
	}
	_ = unknown.Close()
}

func TestStandaloneSTUNCancelIsIdempotent(t *testing.T) {
	test := NewSTUNTest()
	handler := newRecordingSTUNHandler()
	server, endpoint := startLocalSTUNServer(t, false)
	defer server.Close()
	test.Start(endpoint, handler)
	select {
	case <-handler.progress:
	case <-time.After(time.Second):
		t.Fatal("standalone STUN progress missing")
	}
	var waitGroup sync.WaitGroup
	for index := 0; index < 16; index++ {
		waitGroup.Add(1)
		go func() { defer waitGroup.Done(); test.Cancel() }()
	}
	waitGroup.Wait()
	select {
	case message := <-handler.errors:
		if !strings.Contains(message, "cancelled") {
			t.Fatalf("cancel error = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("standalone cancellation callback missing")
	}
	test.Start(endpoint, handler)
	select {
	case message := <-handler.errors:
		if !strings.Contains(message, "single-use") {
			t.Fatalf("second Start error = %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("second Start rejection missing")
	}
}

func startSTUNTestCore(t *testing.T) (*BoxService, *ClashAPIClient) {
	t.Helper()
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
	return service, client
}

func statisticTotals() (int64, int64) {
	return statistic.DefaultManager.Total()
}

func startLocalSTUNServer(t *testing.T, respond bool) (*net.UDPConn, string) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if !respond {
		return connection, connection.LocalAddr().String()
	}
	go func() {
		buffer := make([]byte, 2048)
		count, source, readError := connection.ReadFromUDP(buffer)
		if readError != nil || count < 20 {
			return
		}
		var transactionID [12]byte
		copy(transactionID[:], buffer[8:20])
		response := localSTUNSuccessResponse(transactionID, netip.MustParseAddrPort("198.51.100.20:4567"))
		_, _ = connection.WriteToUDP(response, source)
	}()
	return connection, connection.LocalAddr().String()
}

func localSTUNSuccessResponse(transactionID [12]byte, mapped netip.AddrPort) []byte {
	const (
		responseType = uint16(0x0101)
		cookie       = uint32(0x2112A442)
		mappedType   = uint16(0x0001)
	)
	response := make([]byte, 32)
	binary.BigEndian.PutUint16(response[0:2], responseType)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], cookie)
	copy(response[8:20], transactionID[:])
	binary.BigEndian.PutUint16(response[20:22], mappedType)
	binary.BigEndian.PutUint16(response[22:24], 8)
	response[25] = 1
	binary.BigEndian.PutUint16(response[26:28], mapped.Port())
	copy(response[28:32], mapped.Addr().AsSlice())
	return response
}
