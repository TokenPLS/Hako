package adapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	A "github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outbound"
	"github.com/TokenPLS/Hako/common/utils"
)

func TestURLTestReturnsUnexpectedHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		t.Fatal(err)
	}
	proxy := A.NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = proxy.URLTest(ctx, server.URL, expected)
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 503") {
		t.Fatalf("URLTest status error = %v", err)
	}
}

func TestURLTestNeverUsesZeroForSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		t.Fatal(err)
	}
	proxy := A.NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, server.URL, expected)
	if err != nil {
		t.Fatalf("URLTest: %v", err)
	}
	if delay == 0 {
		t.Fatal("successful URLTest returned the zero failure sentinel")
	}
}
