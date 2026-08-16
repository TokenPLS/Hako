package hako

import (
	"encoding/json"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

func init() {
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/traffic", serveTrafficSnapshot)
		router.Get("/hako/v1/memory", serveMemorySnapshot)
	})
}

func serveTrafficSnapshot(writer http.ResponseWriter, _ *http.Request) {
	manager := statistic.DefaultManager
	up, down := manager.Now()
	upTotal, downTotal := manager.Total()
	writeSnapshotJSON(writer, struct {
		Up        int64 `json:"up"`
		Down      int64 `json:"down"`
		UpTotal   int64 `json:"upTotal"`
		DownTotal int64 `json:"downTotal"`
	}{up, down, upTotal, downTotal})
}

func serveMemorySnapshot(writer http.ResponseWriter, _ *http.Request) {
	writeSnapshotJSON(writer, struct {
		Inuse   uint64 `json:"inuse"`
		OSLimit uint64 `json:"oslimit"`
	}{statistic.DefaultManager.Memory(), 0})
}

func writeSnapshotJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		http.Error(writer, "encode snapshot", http.StatusInternalServerError)
	}
}
