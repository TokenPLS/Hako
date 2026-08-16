package hako

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/http/httptest"
)

// The core has exactly one way to tell a user what it did to their configuration: a log line.
// Seven deviations rely on it and four say nothing at all, which is how `ipv6: false` could
// quietly claim the v6 default route for a year. A log is also the wrong shape -- it is a
// stream, it is not addressable, and a client cannot ask it "what happened to my port".
//
// This is the addressable form. It answers per field, and it answers the four questions a
// reader actually has: what did I write, what happens instead, why, and can I do anything
// about it. The reason categories are the three shapes a deviation can take:
//
//	stripped    -- the field parsed, and this core removed it
//	forced      -- the field parsed, and this core overwrote it
//	unavailable -- the platform has no such facility; nothing could honour it
//
// A field the user never wrote is not a deviation. Clearing raw.Port from zero to zero is
// not something to report, and a report full of those is a report nobody reads.
func TestDeviationReportCoversAllThreeCategoriesFromWhatTheUserWrote(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
ntp:
  enable: true
  write-to-system: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations := configDeviationsForDocument(t, document)

	byField := make(map[string]configDeviation, len(deviations))
	for _, deviation := range deviations {
		if _, duplicate := byField[deviation.Field]; duplicate {
			t.Errorf("%s reported twice", deviation.Field)
		}
		byField[deviation.Field] = deviation
	}

	for field, want := range map[string]string{
		"redir-port":          deviationUnavailable,
		"tproxy-port":         deviationUnavailable,
		"ntp.write-to-system": deviationForced,
	} {
		deviation, reported := byField[field]
		if !reported {
			t.Errorf("%s was changed but is not reported; the user has no way to learn it", field)
			continue
		}
		if deviation.Category != want {
			t.Errorf("%s category = %q, want %q", field, deviation.Category, want)
		}
		if deviation.Given == "" {
			t.Errorf("%s does not carry what the user wrote; a report the reader cannot match "+
				"against their own file is not addressable", field)
		}
		if deviation.Effective == "" {
			t.Errorf("%s does not say what happens instead", field)
		}
		if deviation.Source == "" {
			t.Errorf("%s carries no citation. Every deviation owes either an Apple source or a "+
				"measurement of ours -- that rule is what this whole batch exists to enforce", field)
		}
	}

	// Three written fields plus the two this core overwrites from silence. Naming the
	// expected set rather than a count is what keeps this a noise guard: a new rule that
	// fires on a document which does not carry its field shows up here as a name.
	want := map[string]bool{
		"redir-port": true, "tproxy-port": true, "ntp.write-to-system": true,
		"dns.enable": true, "find-process-mode": true, "profile.store-fake-ip": true,
	}
	for field := range byField {
		if !want[field] {
			t.Errorf("%s is reported for a document that does not deviate in it", field)
		}
	}
	if len(deviations) != len(want) {
		t.Errorf("reported %d deviations, want %d: %v", len(deviations), len(want), fieldsOf(deviations))
	}
}

// Silence is the failure mode being fixed, but noise is how a report becomes silence again.
// A silent configuration is entitled to a short answer: exactly the fields this core
// overwrites regardless of what was written, and nothing else. Anything more and the reader
// learns to skip the list, which puts us back where we started by a longer road.
func TestASilentConfigurationReportsOnlyWhatItStillChanges(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	reported := map[string]bool{}
	for _, deviation := range configDeviationsForDocument(t, silent) {
		reported[deviation.Field] = true
	}
	silentlyChanged := map[string]bool{
		"dns.enable": true, "find-process-mode": true, "profile.store-fake-ip": true,
	}
	for field := range reported {
		if !silentlyChanged[field] {
			t.Errorf("%s is reported for a reader who wrote nothing and whose behaviour it does "+
				"not change", field)
		}
	}
	if len(reported) != len(silentlyChanged) {
		t.Errorf("silent configuration reported %d deviations, want %d: %v",
			len(reported), len(silentlyChanged), reported)
	}
}

// Recoverable says whether editing the configuration can get the behaviour back. It is the
// difference between "delete this line, it does nothing" and "this cannot work here at all",
// and a client that cannot tell them apart will phrase both the same way.
func TestRecoverabilityDistinguishesAPlatformWallFromOurChoice(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, document) {
		// Recoverable is the narrow claim that writing the field yourself gets your value.
		// It is true for exactly the deviations that only change a default, and false for
		// everything this core removes or overrides -- telling a user to go edit a file that
		// cannot help them is the failure this separation exists to prevent.
		if deviation.Recoverable && deviation.Category != deviationForced {
			t.Errorf("%s is %s yet claims editing the configuration alone restores it",
				deviation.Field, deviation.Category)
		}
		if deviation.Recoverable && deviation.Alternative == "" {
			t.Errorf("%s says it is recoverable without saying how", deviation.Field)
		}
		switch deviation.Field {
		case "tproxy-port":
			if deviation.Alternative != "" {
				t.Errorf("tproxy-port offers an alternative (%q), but upstream's own "+
					"setsockopt_other.go answers 'not supported on current platform' and no "+
					"Apple facility replaces it", deviation.Alternative)
			}
		case "redir-port":
			if deviation.Alternative != "" {
				t.Errorf("redir-port offers an alternative (%q); nothing on Apple replaces it", deviation.Alternative)
			}
			if !strings.Contains(deviation.Reason+deviation.Source, "/dev/pf") {
				t.Error("redir-port does not cite the platform fact that justifies it")
			}
		}
	}
}

// Start-time reachability is the whole point: the plan is computed before activation, so a
// client that only ever saw the plan cannot answer "what is my running core doing".
func TestDeviationRouteServesWhatTheRunningCoreDecided(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })

	publishDeviations([]configDeviation{{
		Field: "port", Given: "7890", Effective: "no listener is opened",
		Category: deviationStripped, Reason: "product decision", Source: "proxy_share.go:313",
		Recoverable: true,
	}})

	recorder := httptest.NewRecorder()
	serveConfigDeviations(recorder, httptest.NewRequest("GET", "/hako/v1/deviations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	var body struct {
		SchemaVersion int               `json:"schemaVersion"`
		Deviations    []configDeviation `json:"deviations"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %s", recorder.Body.String())
	}
	if len(body.Deviations) != 1 || body.Deviations[0].Field != "port" {
		t.Fatalf("endpoint did not serve the published list: %s", recorder.Body.String())
	}
	if body.SchemaVersion == 0 {
		t.Error("no schema version; a client cannot tell an empty list from an older core that " +
			"never published one")
	}
}

// An unstarted core has published nothing, and must say so as an empty list rather than a
// null a client would render as "no problems".
func TestDeviationRouteAnswersBeforeAnythingIsPublished(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	recorder := httptest.NewRecorder()
	serveConfigDeviations(recorder, httptest.NewRequest("GET", "/hako/v1/deviations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	if body := recorder.Body.String(); !json.Valid([]byte(body)) {
		t.Fatalf("response is not JSON: %s", body)
	}
	var body struct {
		Deviations []configDeviation `json:"deviations"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body.Deviations == nil {
		t.Error("deviations is null before Start; an empty array is the honest answer")
	}
}

func configDeviationsForDocument(t *testing.T, document string) []configDeviation {
	t.Helper()
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return deviations
}

func fieldsOf(deviations []configDeviation) []string {
	fields := make([]string, 0, len(deviations))
	for _, deviation := range deviations {
		fields = append(fields, deviation.Field)
	}
	return fields
}

// Some fields are overwritten whether or not the user wrote them, and those are the ones a
// report keyed on "did they write it" cannot see. A silent configuration on this core still
// answers DNS and still never looks up a process -- both differ from what the same file does
// on mihomo, and a reader who wrote nothing is exactly the reader least likely to guess it.
//
// dns.enable: upstream DefaultRawConfig has false; this core forces true because an Apple
// packet tunnel captures port 53 regardless, so false would mean every captured query
// answers SERVFAIL. find-process-mode: upstream defaults to strict; this core forces off.
func TestDeviationsFromSilenceAreReportedToo(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	byField := make(map[string]configDeviation)
	for _, deviation := range configDeviationsForDocument(t, silent) {
		byField[deviation.Field] = deviation
	}

	for _, field := range []string{"dns.enable", "find-process-mode"} {
		deviation, reported := byField[field]
		if !reported {
			t.Errorf("%s is overwritten even when unwritten, and is not reported; a silent "+
				"configuration behaves differently from mihomo's and nobody is told", field)
			continue
		}
		if deviation.Category != deviationForced {
			t.Errorf("%s category = %q, want %q", field, deviation.Category, deviationForced)
		}
		if deviation.Given == "" {
			t.Errorf("%s must still say what mihomo would have used; the reader wrote nothing, "+
				"so the only useful baseline is upstream's default", field)
		}
	}
}

// The mirror of the case above: a field this core forces to the value upstream already uses
// changes nothing for a silent reader, and reporting it would be noise. ntp.write-to-system
// is forced false and upstream's default is false.
func TestForcingAValueUpstreamAlreadyDefaultsToIsNotADeviation(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, silent) {
		if deviation.Field == "ntp.write-to-system" {
			t.Error("ntp.write-to-system is reported for a reader who never wrote it, but " +
				"upstream's own default is false as well -- nothing differs")
		}
	}
}

// The report has to come from the configuration that is running, and it has to keep coming.
// A reload that changes what is deviating and leaves the old answer standing turns the
// endpoint into a fresh way to be misinformed -- worse than the log it replaced, because a
// log at least has timestamps.
func TestRuntimeParseRepublishesOnEveryStartAndReload(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	const withPort = `
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, _, err := parseConfigForIOSRuntime(withPort, true); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reportsField(loadPublishedDeviations(), "redir-port") {
		t.Fatalf("a Start-path parse did not publish: %v", fieldsOf(loadPublishedDeviations()))
	}

	const withoutPort = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, _, err := parseConfigForIOSRuntime(withoutPort, true); err != nil {
		t.Fatalf("reload parse: %v", err)
	}
	if reportsField(loadPublishedDeviations(), "redir-port") {
		t.Errorf("redir-port is still reported after a reload that removed it: %v", fieldsOf(loadPublishedDeviations()))
	}
}

// CheckConfig validates a candidate the user has not activated. Publishing from it would
// overwrite what the running core reported with what some other file would have done.
func TestValidatingACandidateDoesNotOverwriteTheRunningReport(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })

	publishDeviations([]configDeviation{{Field: "running-marker", Category: deviationStripped}})

	const candidate = `
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := parseConfigForIOS(candidate, true); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reportsField(loadPublishedDeviations(), "running-marker") {
		t.Errorf("validating a candidate replaced the running core's report: %v",
			fieldsOf(loadPublishedDeviations()))
	}
}

func reportsField(deviations []configDeviation, field string) bool {
	for _, deviation := range deviations {
		if deviation.Field == field {
			return true
		}
	}
	return false
}

// The report renders what the user wrote back to them, and some of what they write is a
// credential. It goes to two outlets at once -- an HTTP response and a log line that lands on
// disk at any level in any build -- so a plaintext secret here is the credential red line
// broken twice by one struct field.
//
// This is an outlet constraint, not an internal invariant: the parsed configuration keeps the
// real value, exactly as the user supplied it. Only what leaves the process is withheld.
func TestCredentialBearingFieldsNeverRenderTheirValue(t *testing.T) {
	const document = `
secret: hunter2
authentication:
  - "alice:correct-horse"
tls:
  private-key: |
    -----BEGIN PRIVATE KEY-----
    NOTAREALKEY
tuic-server:
  enable: true
  token:
    - deadbeefdeadbeef
  users:
    bob: swordfish
ss-config: "ss://chacha20-ietf-poly1305:tell-nobody@:8388"
vmess-config: "vmess://11111111-2222-3333-4444-555555555555"
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	secrets := []string{
		"hunter2", "correct-horse", "NOTAREALKEY", "deadbeefdeadbeef",
		"swordfish", "tell-nobody", "11111111-2222-3333-4444-555555555555",
	}
	deviations := configDeviationsForDocument(t, document)
	if len(deviations) == 0 {
		t.Fatal("nothing was reported, so this test proves nothing")
	}
	for _, deviation := range deviations {
		rendered := deviation.Field + "|" + deviation.Given + "|" + deviation.Effective + "|" +
			deviation.Reason + "|" + deviation.Source + "|" + deviation.Alternative
		for _, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Errorf("%s renders a credential the user supplied; this goes to an HTTP "+
					"response and to a log line on disk", deviation.Field)
			}
		}
	}
}

// Withholding has to stay narrow. A port number is not a secret, and a report that says
// "value withheld" for everything is a report that tells the reader nothing about their file.
func TestNonCredentialFieldsStillShowWhatTheUserWrote(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, document) {
		switch deviation.Field {
		case "redir-port":
			if deviation.Given != "7896" {
				t.Errorf("redir-port given = %q, want the value the user wrote", deviation.Given)
			}
		case "tproxy-port":
			if deviation.Given != "7895" {
				t.Errorf("tproxy-port given = %q, want the value the user wrote", deviation.Given)
			}
		}
	}
}
