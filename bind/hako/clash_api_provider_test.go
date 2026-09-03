package hako

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestClashAPIClientUpdatesProvidersOverNativeUnixAPI(t *testing.T) {
	path := shortClashSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Method + " " + request.RequestURI
		writer.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	client, err := NewClashAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProxyProvider("proxy/name"); err != nil {
		t.Fatalf("UpdateProxyProvider: %v", err)
	}
	if err := client.UpdateRuleProvider("rule name"); err != nil {
		t.Fatalf("UpdateRuleProvider: %v", err)
	}

	want := []string{
		"PUT /providers/proxies/proxy%2Fname",
		"PUT /providers/rules/rule%20name",
	}
	for _, expected := range want {
		if got := <-requests; got != expected {
			t.Fatalf("provider update request = %q, want %q", got, expected)
		}
	}
}

func TestClashAPIClientReadsProviderCatalogAndRunsHealthCheck(t *testing.T) {
	path := shortClashSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Method + " " + request.RequestURI
		if strings.HasSuffix(request.URL.Path, "/healthcheck") {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"providers": map[string]any{}})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	client, err := NewClashAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := client.GetProxyProviders(); err != nil || !json.Valid([]byte(payload)) {
		t.Fatalf("GetProxyProviders = %q, %v", payload, err)
	}
	if payload, err := client.GetProxyProvider("proxy/name"); err != nil || !json.Valid([]byte(payload)) {
		t.Fatalf("GetProxyProvider = %q, %v", payload, err)
	}
	if err := client.HealthCheckProxyProvider("proxy/name"); err != nil {
		t.Fatalf("HealthCheckProxyProvider: %v", err)
	}
	if payload, err := client.GetRuleProviders(); err != nil || !json.Valid([]byte(payload)) {
		t.Fatalf("GetRuleProviders = %q, %v", payload, err)
	}

	want := []string{
		"GET /providers/proxies",
		"GET /providers/proxies/proxy%2Fname",
		"GET /providers/proxies/proxy%2Fname/healthcheck",
		"GET /providers/rules",
	}
	for _, expected := range want {
		if got := <-requests; got != expected {
			t.Fatalf("provider request = %q, want %q", got, expected)
		}
	}
}

func TestClashAPIClientRejectsEmptyProviderUpdateNames(t *testing.T) {
	client, err := NewClashAPIClient("/tmp/does-not-exist.sock", newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProxyProvider(""); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("empty proxy provider name error = %v", err)
	}
	if err := client.UpdateRuleProvider(""); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("empty rule provider name error = %v", err)
	}
	if _, err := client.GetProxyProvider(""); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("empty proxy provider detail name error = %v", err)
	}
	if err := client.HealthCheckProxyProvider(""); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("empty proxy provider health name error = %v", err)
	}
}
