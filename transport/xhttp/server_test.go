package xhttp

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

type retainingResponseWriter struct {
	header  http.Header
	payload []byte
}

func (w *retainingResponseWriter) Header() http.Header {
	return w.header
}

func (w *retainingResponseWriter) Write(payload []byte) (int, error) {
	w.payload = payload
	return len(payload), nil
}

func (w *retainingResponseWriter) WriteHeader(int) {}

func TestHTTPServerConnWriteTransfersStablePayload(t *testing.T) {
	w := &retainingResponseWriter{header: make(http.Header)}
	conn := newHTTPServerConn(w, io.NopCloser(strings.NewReader("")))
	payload := []byte("stable")

	n, err := conn.Write(payload)
	assert.NoError(t, err)
	assert.Equal(t, len(payload), n)

	payload[0] = 'X'
	assert.Equal(t, []byte("stable"), w.payload)
}

func TestServerHandlerModeRestrictions(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "StreamOneAcceptsStreamOne",
			mode:       "stream-one",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamOneRejectsSessionDownload",
			mode:       "stream-one",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "StreamUpAcceptsStreamOne",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpAllowsDownloadEndpoint",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsPacketUpload",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpAllowsDownloadEndpoint",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpRejectsStreamOne",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamUpUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				Path: "/xhttp",
				Mode: testCase.mode,
			}
			handler, err := NewServerHandler(ServerOption{
				Config: config,
				ConnHandler: func(conn net.Conn) {
					_ = conn.Close()
				},
			})
			assert.NoError(t, err)

			req := httptest.NewRequest(testCase.method, testCase.target, io.NopCloser(http.NoBody))
			recorder := httptest.NewRecorder()

			err = config.FillStreamRequest(req, "")
			assert.NoError(t, err)

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, testCase.wantStatus, recorder.Result().StatusCode)
		})
	}
}
