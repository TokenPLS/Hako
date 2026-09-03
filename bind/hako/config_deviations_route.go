package hako

import (
	"encoding/json"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

func init() {
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/deviations", serveConfigDeviations)
	})
}

// serveConfigDeviations answers what the running core did to the user's configuration.
//
// It is deliberately readable whether or not anything was published: a core that has not
// started yet answers with an empty list, not an error and not null. A client rendering
// "no deviations" for a null it could not distinguish from "not asked yet" would be
// reporting silence as health, which is the bug this endpoint exists to end.
func serveConfigDeviations(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	// sequence / entry / document are additive (schemaVersion stays 1): a client that
	// ignores them reads exactly what it read before. document is absent until the first
	// publish -- there is no document to name yet, and a made-up identity would be matched
	// by nothing.
	payload := struct {
		SchemaVersion int                        `json:"schemaVersion"`
		Sequence      uint64                     `json:"sequence"`
		Entry         string                     `json:"entry,omitempty"`
		Document      *deviationDocumentIdentity `json:"document,omitempty"`
		Deviations    []configDeviation          `json:"deviations"`
	}{SchemaVersion: configDeviationSchemaVersion, Deviations: []configDeviation{}}
	if report := loadPublishedDeviationReport(); report != nil {
		payload.Sequence, payload.Entry = report.Sequence, report.Entry
		identity := report.Document
		payload.Document = &identity
		payload.Deviations = report.Deviations
	}
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		http.Error(writer, "encode deviations", http.StatusInternalServerError)
	}
}
