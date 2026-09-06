package hako

import (
	"io"
	"mime"
	"strings"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

func init() {
	route.Register(func(router chi.Router) {
		router.Put("/hako/v1/providers/side-update", serveProviderSideUpdate)
	})
}

func serveProviderSideUpdate(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, mediaTypeError := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaTypeError != nil || mediaType != "application/octet-stream" {
		http.Error(writer, "content type must be application/octet-stream", http.StatusUnsupportedMediaType)
		return
	}
	kind := request.URL.Query().Get("kind")
	name := request.URL.Query().Get("name")
	if (kind != "proxy" && kind != "rule") || !validProviderSideUpdateName(name) {
		http.Error(writer, "invalid provider selector", http.StatusBadRequest)
		return
	}
	if request.ContentLength > maximumProviderResourceBytes {
		http.Error(writer, "provider payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, int64(maximumProviderResourceBytes)+1))
	if err != nil {
		http.Error(writer, "invalid provider payload", http.StatusBadRequest)
		return
	}
	if len(payload) == 0 {
		http.Error(writer, "provider payload is empty", http.StatusBadRequest)
		return
	}
	if len(payload) > maximumProviderResourceBytes {
		http.Error(writer, "provider payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	if err := service.sideUpdateProvider(kind, name, payload); err != nil {
		// Provider names, paths, credentials, and payload diagnostics stay out of
		// the cross-process response. The caller only needs a fail-closed result.
		http.Error(writer, "provider side update rejected", http.StatusUnprocessableEntity)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func validProviderSideUpdateName(name string) bool {
	return name != "" && len(name) <= 512 && strings.IndexFunc(name, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}
