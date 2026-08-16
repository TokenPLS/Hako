package route

import (
	"fmt"
	"os"

	"github.com/TokenPLS/Hako/component/updater"
	"github.com/TokenPLS/Hako/log"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func upgradeRouter() http.Handler {
	r := chi.NewRouter()
	// /ui is deliberately outside the gate, and the reason the gate gave for it was disproved by
	// this build's own behaviour. "No network acquisition inside the extension" is true of
	// upgradeCore and updateGeoDatabases. It is NOT true of the dashboard, because
	// hub/executor/executor.go:457 calls AutoDownloadUI on the start path, and
	// component/updater/update_ui.go:83 and :94 route both AutoDownloadUI and DownloadUI into
	// the same u.downloadUI(). The automatic one is the more dangerous of the two: it runs
	// synchronously during startup and was measured adding six seconds to a first connection.
	//
	// So the route asks for nothing this core is not already doing unprompted, on a worse
	// schedule. Refusing it was refusing the safer half of a thing we do anyway.
	if !embedMode {
		r.Post("/", upgradeCore) // replaces the binary: code signing forbids it on Apple
	}
	// The geo updater is gated on its own measurement rather than on embedMode: 17 MB of GeoIP
	// fetched and unpacked does not fit an iOS packet tunnel measured dying at 49.5 MiB, and a
	// macOS app extension has no such ceiling (measured living at 62.4 MiB, no limit set).
	if !embedMode || geoUpdaterAllowed {
		r.Post("/geo", updateGeoDatabases)
	}
	r.Post("/ui", updateUI)
	return r
}

func upgradeCore(w http.ResponseWriter, r *http.Request) {
	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L108
	log.Infoln("start update")
	execPath, err := os.Executable()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("getting path: %s", err)))
		return
	}

	query := r.URL.Query()
	channel := query.Get("channel")
	force := query.Get("force") == "true"

	err = updater.DefaultCoreUpdater.Update(execPath, channel, force)
	if err != nil {
		log.Warnln("%s", err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("%s", err)))
		return
	}

	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go restartExecutable(execPath)
}

func updateUI(w http.ResponseWriter, r *http.Request) {
	err := updater.DefaultUiUpdater.DownloadUI()
	if err != nil {
		log.Warnln("%s", err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("%s", err)))
		return
	}

	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
