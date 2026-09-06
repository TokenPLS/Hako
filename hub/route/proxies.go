package route

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

var (
	SwitchProxiesCallback func(sGroup string, sProxy string)
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Put("/", updateProxy)
		r.Delete("/", unfixedProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxies := tunnel.Proxies()
		proxy, exist := proxies[name]
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := tunnel.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	render.JSON(w, r, proxy)
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Name string `json:"name"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if err := selector.Set(req.Name); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}

	cachefile.Cache().SetSelected(proxy.Name(), req.Name)
	if SwitchProxiesCallback != nil {
		// refresh tray menu
		go SwitchProxiesCallback(proxy.Name(), req.Name)
	}
	render.NoContent(w, r)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	// Derived from the request, not Background, so a caller that hangs up
	// takes its probe with it. Background kept an abandoned probe dialing and
	// waiting for the full `timeout` on its own -- one orphaned goroutine and
	// socket per abandoned probe, a sweep of dead nodes at a time (~68KB each
	// on device; the pad between a surviving sweep and a jetsam kill). The
	// sibling group-delay handler has derived from r.Context() upstream all
	// along; this makes the probe family answer hang-ups the same way.
	ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
	defer cancel()

	// `expected` keeps upstream's contract: parsed from the request, nil when
	// absent. What changes is where "answered, but not with that status" is
	// read from: the outcome, not an error that would have marked the proxy
	// dead for every URL (adapter.URLTestOutcome). A proxy that does not
	// provide outcomes takes upstream's path unchanged.
	var delay uint16
	satisfied, status := true, 0
	if outcomes, ok := proxy.(adapter.URLTestOutcomeProvider); ok {
		var outcome adapter.URLTestOutcome
		outcome, err = outcomes.URLTestOutcome(ctx, url, expectedStatus)
		delay, satisfied, status = outcome.Delay, outcome.Satisfied, outcome.HTTPStatus
	} else {
		delay, err = proxy.URLTest(ctx, url, expectedStatus)
	}
	if ctx.Err() != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}

	if err != nil || delay == 0 || !satisfied {
		render.Status(r, http.StatusServiceUnavailable)
		// Hako's App Group-only controller needs the actual dial failure to
		// distinguish timeout/DNS/TLS/authentication from an API outage. The
		// previous delay != 0 guard discarded every normal failure, because
		// failed URL tests necessarily return a zero delay.
		//
		// It also needs it as DATA. `message` alone made the client match a
		// dozen substrings against this tree's English, so rewording a
		// sentence here silently moved a category there with nothing to go
		// red -- and every cause that a substring cannot tell apart arrived on
		// screen as one word. A user
		// loopback resolver; "dns" could not have said that, and the
		// errno can.
		//
		// `message` keeps upstream's shape and its exact sentence for
		// every existing reader; the classification travels beside it.
		sentence := "An error occurred in the delay test"
		switch {
		case err != nil:
			sentence = err.Error()
		case !satisfied:
			sentence = fmt.Sprintf("unexpected HTTP status %d from URL test target", status)
		}
		answer := render.M{"message": sentence, "httpStatus": status}
		// A deferred probe is not a failure: the memory admission gate skipped
		// it and the node keeps whatever it knew before. It is a sentinel
		// (adapter.ErrURLTestDeferred), so this reads its type rather than the
		// fixed sentence the client used to recognise.
		if errors.Is(err, adapter.ErrURLTestDeferred) {
			answer["deferred"] = true
		} else if failure := adapter.ClassifyURLTestFailure(err, satisfied, status); failure != nil {
			answer["failure"] = render.M{
				"kind":    failure.Kind,
				"errno":   failure.Errno,
				"message": failure.Message,
			}
		}
		render.JSON(w, r, answer)
		return
	}

	render.JSON(w, r, render.M{
		"delay": delay,
	})
}

func unfixedProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
		render.NoContent(w, r)
		return
	}
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, ErrBadRequest)
}
