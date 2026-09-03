package hako

import (
	"encoding/json"
	"errors"
	"io"
	"mime"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

const proxyShareMaximumRequestBytes = 2048

type proxyShareRequest struct {
	Port     int32  `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func init() {
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/proxy-share", serveProxyShareStatus)
		router.Put("/hako/v1/proxy-share", serveProxyShareStart)
		router.Delete("/hako/v1/proxy-share", serveProxyShareStop)
	})
}

func serveProxyShareStatus(writer http.ResponseWriter, _ *http.Request) {
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func serveProxyShareStart(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if request.ContentLength > proxyShareMaximumRequestBytes {
		http.Error(writer, "proxy-share request too large", http.StatusRequestEntityTooLarge)
		return
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, proxyShareMaximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	var input proxyShareRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid proxy-share request", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(writer, "invalid proxy-share request", http.StatusBadRequest)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	if err := service.StartProxyShare(input.Port, input.Username, input.Password); err != nil {
		// Credentials and listener details never cross the process boundary in
		// an error. The App only needs a fail-closed result -- with one
		// exception: an unavailable port is the single rejection the user can
		// act on, and the App cannot predict it (the wildcard share collides
		// with a config's loopback listener on iOS and not on macOS). So that
		// one is named, by port number only; its cause stays wrapped and
		// unrendered.
		var portUnavailable proxySharePortUnavailableError
		if errors.As(err, &portUnavailable) {
			http.Error(writer, portUnavailable.Error(), http.StatusConflict)
			return
		}
		http.Error(writer, "proxy share rejected", http.StatusUnprocessableEntity)
		return
	}
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func serveProxyShareStop(writer http.ResponseWriter, _ *http.Request) {
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	_ = service.StopProxyShare()
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func writeProxyShareStatus(writer http.ResponseWriter, payload string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, payload)
}
