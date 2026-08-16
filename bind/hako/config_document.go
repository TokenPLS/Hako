package hako

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/TokenPLS/Hako/config"
	"gopkg.in/yaml.v3"
)

// documentViews is what one Open produced: immutable from birth. Queries load
// the pointer once and work off that snapshot, so a Close racing a query never
// yields a torn read -- the in-flight query keeps its snapshot alive and
// completes; only queries that start after Close refuse.
type documentViews struct {
	rawText string
	root    map[string]any
	raw     *config.RawConfig
}

// ConfigDocument holds one parsed configuration for the duration of one
// activation or one editor preparation: open, ask it what you need -- the
// resource plan, one or more projections -- and Close it. The generic root and
// the typed RawConfig are the same two decodes PlanResourcesForIOS has always
// performed; the difference is they now happen once per flow instead of once
// per export.
//
// It is deliberately NOT a long-lived cache. Cross-flow reuse belongs to the
// persisted projection keyed by revision; a reader's configuration does not
// stay resident in Go beyond the flow that needed it.
//
// Concurrency: the views are immutable and reached through one atomic pointer
// load per query. A first draft nil-ed the fields directly under an atomic
// bool and read them after a separate flag check -- a check-then-read window
// the race detector happened not to trip over in one run; the snapshot shape
// removes the window instead of hoping the scheduler keeps missing it. Close
// is idempotent (the BoxService / ClashAPIClient precedents).
type ConfigDocument struct {
	views atomic.Pointer[documentViews]
}

func NewConfigDocument(configContent string) (*ConfigDocument, error) {
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(configContent), &root); err != nil {
		return nil, fmt.Errorf("hako: parse config: %w", err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, fmt.Errorf("hako: parse config: %w", err)
	}
	doc := &ConfigDocument{}
	doc.views.Store(&documentViews{rawText: configContent, root: root, raw: raw})
	// Backstop only: the contract is an explicit Close. A dropped handle must
	// still not pin megabytes of a reader's configuration until process exit.
	runtime.SetFinalizer(doc, func(d *ConfigDocument) { d.Close() })
	return doc, nil
}

// Close releases the parsed views. Idempotent; a closed document refuses every
// new query with an error rather than a crash, while queries already holding a
// snapshot complete against it.
func (d *ConfigDocument) Close() {
	if d.views.Swap(nil) != nil {
		runtime.SetFinalizer(d, nil)
	}
}

// snapshot returns the views or an error once closed. Every query calls it
// exactly once and threads the result through, never re-loading mid-query.
func (d *ConfigDocument) snapshot() (*documentViews, error) {
	views := d.views.Load()
	if views == nil {
		return nil, fmt.Errorf("hako: config document is closed")
	}
	return views, nil
}

func (d *ConfigDocument) closedErr() error {
	_, err := d.snapshot()
	return err
}

// ProjectionJSON returns one compact JSON document (gomobile cannot bind maps
// or slices, iterator.go:8; packagesJSON is a JSON array for the same reason).
// Unknown packages and empty lists are caller bugs and are refused by name --
// a silent empty result would send the caller looking in the wrong place.
func (d *ConfigDocument) ProjectionJSON(kind string, packagesJSON string) (*StringBox, error) {
	var packages []string
	if err := json.Unmarshal([]byte(packagesJSON), &packages); err != nil {
		return nil, fmt.Errorf("hako: parse projection package list: %w", err)
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("hako: projection requested with no packages")
	}
	for _, name := range packages {
		switch name {
		case projectionPackageCatalog, projectionPackageResources,
			projectionPackageRuleFacts, projectionPackageScalars:
		default:
			return nil, fmt.Errorf("hako: unknown projection package %q", name)
		}
	}
	projection, err := buildConfigProjection(d, kind, packages)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return nil, err
	}
	if err := validateConfigurationJSONResult(string(payload)); err != nil {
		return nil, err
	}
	return WrapString(string(payload)), nil
}
