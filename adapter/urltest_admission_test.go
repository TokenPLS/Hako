package adapter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter/outbound"
)

func admissionTestProxy(t *testing.T) *Proxy {
	t.Helper()
	h, err := outbound.NewHttp(outbound.HttpOption{
		Name:   "admission-probe",
		Server: "127.0.0.1",
		Port:   1, // nothing listens; the dial fails fast
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewProxy(h)
}

func TestURLTestAdmissionHookRunsWhenSet(t *testing.T) {
	var calls atomic.Int64
	SetURLTestAdmission(func(ctx context.Context) error { calls.Add(1); return nil })
	defer SetURLTestAdmission(nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = admissionTestProxy(t).URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if got := calls.Load(); got != 1 {
		t.Fatalf("armed hook must run once per URL test, got %d", got)
	}
}

func TestURLTestAdmissionNilHookKeepsUpstreamPath(t *testing.T) {
	SetURLTestAdmission(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The default is upstream's exact path: no admission callback, no panic.
	_, err := admissionTestProxy(t).URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if err == nil {
		t.Fatal("dial against a closed port should fail")
	}
}

func TestURLTestDeferredSkipsBookkeeping(t *testing.T) {
	SetURLTestAdmission(func(ctx context.Context) error { return ErrURLTestDeferred })
	defer SetURLTestAdmission(nil)

	p := admissionTestProxy(t)
	before := p.AliveForTestUrl("https://www.gstatic.com/generate_204")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := p.URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if !errors.Is(err, ErrURLTestDeferred) {
		t.Fatalf("deferred probe must surface ErrURLTestDeferred, got %v", err)
	}
	if got := p.AliveForTestUrl("https://www.gstatic.com/generate_204"); got != before {
		t.Fatalf("a deferred probe must not touch alive state: %t -> %t", before, got)
	}
	if h := p.DelayHistory(); len(h) != 0 {
		t.Fatalf("a deferred probe must not write history, got %d records", len(h))
	}
}

func TestBackgroundProbeMarkRoundtrip(t *testing.T) {
	if IsBackgroundProbe(context.Background()) {
		t.Fatal("plain context must not read as background")
	}
	if !IsBackgroundProbe(WithBackgroundProbe(context.Background())) {
		t.Fatal("marked context must read as background")
	}
}
