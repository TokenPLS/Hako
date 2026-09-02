package route

import (
	"encoding/json"
	"io"

	"github.com/TokenPLS/Hako/component/profile/cachefile"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func storageRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage)
	// Not gated. The comment here used to read "embedded apps own persistence outside the native
	// API", and that was a design preference wearing the clothes of a constraint. The concrete
	// worry attached to it later -- two processes writing one bbolt file -- was checked and does
	// not hold: nothing in the containing app opens cache.db. It talks to the extension over the
	// App Group socket, and the only writer is the Go code inside the extension.
	//
	// Against the repository's own test for an invented constraint (stricter than upstream AND
	// not required by the platform), this was both. Upstream serves all three verbs; writing a
	// key here touches no configuration, downloads nothing, and contends with nobody.
	//
	// One thing genuinely unmeasured, recorded rather than used as a reason: bbolt is mmap-backed,
	// so a dashboard writing a large scratch value grows the extension's footprint, and this
	// product has been killed at 40 MiB. If that turns out to matter the answer is a size limit,
	// not a closed door -- setStorage already refuses payloads over 1 MiB.
	r.Put("/{key}", setStorage)
	r.Delete("/{key}", deleteStorage)
	return r
}

func getStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data := cachefile.Cache().GetStorage(key)
	w.Header().Set("Content-Type", "application/json")
	if len(data) == 0 {
		w.Write([]byte("null"))
		return
	}
	w.Write(data)
}

func setStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if !json.Valid(data) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(data) > 1024*1024 {
		render.Status(r, http.StatusRequestEntityTooLarge)
		render.JSON(w, r, newError("payload exceeds 1MB limit"))
		return
	}
	cachefile.Cache().SetStorage(key, data)
	render.NoContent(w, r)
}

func deleteStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	cachefile.Cache().DeleteStorage(key)
	render.NoContent(w, r)
}
