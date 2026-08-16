package hako

import (
	"context"
	"fmt"
	"time"

	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
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
		return fmt.Errorf("hako: proxy group %q not found", group)
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return fmt.Errorf("hako: %q is not a selectable group", group)
	}
	if err := selector.Set(name); err != nil {
		return fmt.Errorf("hako: select %q in %q: %w", name, group, err)
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
		return fmt.Errorf("hako: proxy group %q not found", group)
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return fmt.Errorf("hako: %q is not a selectable group", group)
	}
	if _, manual := proxy.Adapter().(*outboundgroup.Selector); manual {
		return fmt.Errorf("hako: %q is a selector; only automatic groups unfix", group)
	}
	selector.ForceSet("")
	cachefile.Cache().SetSelected(group, "")
	return nil
}

// URLTest measures a single proxy's latency against url (empty = default
// generate_204). Returns delay in ms, or -1 on failure — gomobile cannot
// return (uint16, error), so the error is folded into the sentinel.
func URLTest(name, url string) int32 {
	proxy, ok := tunnel.Proxies()[name]
	if !ok {
		return -1
	}
	if url == "" {
		url = defaultURLTestURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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
