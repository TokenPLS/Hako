package hako

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"

	internalSTUN "github.com/TokenPLS/Hako/bind/hako/internal/stun"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

const stunRequestBodyLimit = 4096

func init() {
	route.Register(func(router chi.Router) {
		router.Post("/hako/v1/stun", serveSTUNSession)
	})
}

func serveSTUNSession(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, mediaTypeError := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaTypeError != nil || mediaType != "application/json" {
		http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if request.ContentLength > stunRequestBodyLimit {
		http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, stunRequestBodyLimit+1))
	if err != nil {
		http.Error(writer, "invalid STUN request", http.StatusBadRequest)
		return
	}
	if len(body) > stunRequestBodyLimit {
		http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var wireRequest stunWireRequest
	if err := decoder.Decode(&wireRequest); err != nil {
		http.Error(writer, "invalid STUN request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		http.Error(writer, "invalid STUN request", http.StatusBadRequest)
		return
	}
	if _, err := internalSTUN.NormalizeServer(wireRequest.Server); err != nil {
		http.Error(writer, "invalid STUN server", http.StatusBadRequest)
		return
	}
	if err := validateSTUNOutboundSyntax(wireRequest.Outbound); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming is unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/x-ndjson")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	encoder := json.NewEncoder(writer)
	streamContext, cancel := context.WithCancel(request.Context())
	defer cancel()
	var streamError error
	writeEvent := func(event stunWireEvent) {
		if streamError != nil {
			return
		}
		if err := encoder.Encode(event); err != nil {
			streamError = err
			cancel()
			return
		}
		flusher.Flush()
	}
	result, err := service.runSTUN(streamContext, wireRequest.Server, wireRequest.Outbound, func(progress internalSTUN.Progress) {
		writeEvent(stunWireProgress(progress))
	})
	if streamError != nil {
		return
	}
	if err != nil {
		writeEvent(stunWireEvent{Phase: STUNPhaseDone, Final: true, Error: stunPublicError(err)})
		return
	}
	writeEvent(stunWireResult(result))
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateSTUNOutboundSyntax(outbound string) error {
	if len(outbound) > 256 {
		return errors.New("STUN outbound name is too long")
	}
	if strings.IndexFunc(outbound, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return errors.New("STUN outbound name contains control characters")
	}
	return nil
}
