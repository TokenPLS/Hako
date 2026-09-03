package hako

import (
	"context"
	"fmt"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// control.go exposes the in-process control actions: proxy selection,
// url-test, and connection teardown, by calling mihomo's packages directly
// (no HTTP controller). Mode switching lives on BoxService.SetMode.

const defaultURLTestURL = "https://www.gstatic.com/generate_204"

// SelectProxy points a selector group at one of its members and persists the
// choice to the App Group cache (survives restart), mirroring the clash
// /proxies/{group} PUT.
func SelectProxy(group, name string) error {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: proxy group %q not found", group))
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: %q is not a selectable group", group))
	}
	if err := selector.Set(name); err != nil {
		return bridgeSafeError(fmt.Errorf("hako: select %q in %q: %w", name, group, err))
	}
	cachefile.Cache().SetSelected(group, name)
	return nil
}

// UnfixProxy releases a pinned URLTest/Fallback group back to its own
// measurement, mirroring the clash /proxies/{group} DELETE
// (hub/route/proxies.go: ForceSet("") + cache clear). A Selector is refused
// exactly like the kernel route refuses it: a manual group has no automation
// to resume, so "unfix" would silently mean nothing.
func UnfixProxy(group string) error {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: proxy group %q not found", group))
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: %q is not a selectable group", group))
	}
	if _, manual := proxy.Adapter().(*outboundgroup.Selector); manual {
		return bridgeSafeError(fmt.Errorf("hako: %q is a selector; only automatic groups unfix", group))
	}
	selector.ForceSet("")
	cachefile.Cache().SetSelected(group, "")
	return nil
}

// urlTestExpectedStatus is what this entry point calls a pass: the same
// 200-299 the in-app Clash API client sends as `expected`, stated here
// explicitly because the kernel-side URLTest no longer turns an unexpected
// status into an error (that marked the proxy dead for every URL).
var urlTestExpectedStatus = mustStatusRanges("200-299")

func mustStatusRanges(spec string) utils.IntRanges[uint16] {
	ranges, err := utils.NewUnsignedRanges[uint16](spec)
	if err != nil {
		panic("hako: invalid URL test status range " + spec + ": " + err.Error())
	}
	return ranges
}

// URLTest measures a single proxy's latency against url (empty = default
// generate_204). Returns delay in ms, or -1 on failure — gomobile cannot
// return (uint16, error), so the error is folded into the sentinel. An
// answer outside 200-299 is a failure here too, read from the outcome.
func URLTest(name, url string) int32 {
	proxy, ok := tunnel.Proxies()[name]
	if !ok {
		proxy, ok = proxyFromProviders(name)
		if !ok {
			return -1
		}
	}
	return urlTestDelay(proxy, url)
}

// proxyFromProviders finds a node that only a proxy provider has.
//
// `tunnel.Proxies()` is built from the `proxies:` section and the groups
// (config/config.go:962); a provider's members go to `providersMap` (:996)
// and never enter it. Testing by name against that table alone therefore
// answers -1 for every node a subscription brought -- which is where most
// readers' nodes come from. The HTTP control plane already falls back to the
// provider's health-check route for exactly this; a television cannot use
// that plane at all, so the same fallback
// has to exist in the in-process entry point.
//
// A name two providers both claim is refused rather than guessed at. The
// caller asked about one node; measuring an arbitrary one of two reports a
// latency for a node they did not mean, and nothing in the answer tells them
// which they got. The HTTP client learned this first.
func proxyFromProviders(name string) (C.Proxy, bool) {
	var found C.Proxy
	for _, prov := range tunnel.Providers() {
		for _, proxy := range prov.Proxies() {
			if proxy.Name() != name {
				continue
			}
			if found != nil {
				return nil, false
			}
			found = proxy
		}
	}
	return found, found != nil
}

func urlTestDelay(proxy C.Proxy, url string) int32 {
	if url == "" {
		url = defaultURLTestURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if outcomes, ok := proxy.(adapter.URLTestOutcomeProvider); ok {
		outcome, err := outcomes.URLTestOutcome(ctx, url, urlTestExpectedStatus)
		if err != nil || !outcome.Satisfied {
			return -1
		}
		return int32(outcome.Delay)
	}
	delay, err := proxy.URLTest(ctx, url, nil)
	if err != nil {
		return -1
	}
	return int32(delay)
}

// CloseConnection tears down one tracked connection by id (clash
// /connections/{id} DELETE). Returns whether it was found.
func CloseConnection(id string) bool {
	if c := statistic.DefaultManager.Get(id); c != nil {
		_ = c.Close()
		return true
	}
	return false
}

// CloseAllConnections tears down every tracked connection (clash /connections
// DELETE), e.g. after a mode switch so flows re-resolve under the new rules.
func CloseAllConnections() {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
}
