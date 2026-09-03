package hako

import (
	"encoding/json"
	"io"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

const maximumModeRequestBytes = 1_024

func init() {
	route.Register(func(router chi.Router) {
		router.Patch("/hako/v1/configs/mode", serveModeUpdate)
	})
}

func serveModeUpdate(writer http.ResponseWriter, request *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumModeRequestBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumModeRequestBytes {
		http.Error(writer, "invalid mode request", http.StatusBadRequest)
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		http.Error(writer, "invalid mode request", http.StatusBadRequest)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Hako service is not running", http.StatusServiceUnavailable)
		return
	}
	if err := service.SetMode(body.Mode); err != nil {
		http.Error(writer, "invalid mode", http.StatusBadRequest)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}
