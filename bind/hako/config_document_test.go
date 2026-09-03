package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewConfigDocumentParsesOnceAndServesBothViews(t *testing.T) {
	doc, err := NewConfigDocument("proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\nmode: global\n")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer doc.Close()
	views, err := doc.snapshot()
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if views.raw == nil || len(views.raw.Proxy) != 1 {
		t.Fatalf("typed view missing: %+v", views.raw)
	}
	if views.root == nil {
		t.Fatal("generic view missing")
	}
	if _, present := views.root["mode"]; !present {
		t.Fatal("generic view lost a declared key")
	}
}

func TestCloseIsIdempotentAndUseAfterCloseErrs(t *testing.T) {
	doc, err := NewConfigDocument("proxies: []\n")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	doc.Close()
	doc.Close() // second close must not panic
	if err := doc.closedErr(); err == nil {
		t.Fatal("a closed document must refuse to serve")
	}
}

func TestOpenRefusesWhatTheKernelRefuses(t *testing.T) {
	if _, err := NewConfigDocument("- a\n- list\n"); err == nil {
		t.Fatal("a non-mapping root was accepted")
	}
}

// The concurrency contract: reads from any goroutine while another closes.
// This test exists to give the race detector something real to chew on --
// without it, "safe under -race" would be an untested claim.
func TestConcurrentReadsAndCloseAreRaceFree(t *testing.T) {
	doc, err := NewConfigDocument("proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\n")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				// Exactly the production pattern: one snapshot per query,
				// used throughout. A snapshot taken before Close stays fully
				// readable; after Close, snapshot() refuses.
				if views, err := doc.snapshot(); err == nil {
					_ = views.root
					_ = len(views.raw.Proxy)
				}
			}
		}()
	}
	doc.Close()
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestProjectionJSONReturnsOneCompactDocument(t *testing.T) {
	doc := mustOpen(t, "proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\n")
	box, err := doc.ProjectionJSON(projectionKindSource, `["catalog"]`)
	if err != nil {
		t.Fatalf("projection failed: %v", err)
	}
	var decoded struct {
		SchemaVersion int    `json:"schemaVersion"`
		DocumentKind  string `json:"documentKind"`
		Catalog       *struct {
			Proxies []struct{ Name, Type string } `json:"proxies"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal([]byte(box.Value), &decoded); err != nil {
		t.Fatalf("result does not decode: %v", err)
	}
	if decoded.DocumentKind != "source" || decoded.Catalog == nil ||
		len(decoded.Catalog.Proxies) != 1 {
		t.Fatalf("wrong projection: %+v", decoded)
	}
}

func TestProjectionJSONRefusesUnknownPackagesAndEmptyLists(t *testing.T) {
	doc := mustOpen(t, "proxies: []\n")
	if _, err := doc.ProjectionJSON(projectionKindSource, `["catalog","not-a-package"]`); err == nil ||
		!strings.Contains(err.Error(), "not-a-package") {
		t.Fatalf("unknown package must be refused by name, got %v", err)
	}
	if _, err := doc.ProjectionJSON(projectionKindSource, `[]`); err == nil {
		t.Fatal("an empty package list was accepted")
	}
	if _, err := doc.ProjectionJSON("neither", `["catalog"]`); err == nil {
		t.Fatal("an unknown document kind was accepted")
	}
}
