package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ConfigDeviationsJSON answers what this core WOULD do to a configuration, without starting
// anything.
//
// /hako/v1/deviations describes the configuration that is running, which is the right shape
// for a diagnostic and the wrong one for an editor: a reader looking at a field page while
// disconnected is at the exact moment they are deciding what to write, and that is when the
// page had nothing to say about allow-lan or tun.auto-route. Telling them only after they
// connect is the silence this whole batch exists to end.
//
// It runs the same walk the start path runs -- collectConfigDeviations over the same
// deviationRules with the same policy -- so the sentences a reader sees before connecting and
// after connecting are produced by one piece of code. A second, static list of the same facts
// was the alternative, and two texts that must agree is a drift the reader eventually reads
// as a contradiction.
//
// configContent is the merged YAML the reader would run; targetProfile names the runtime
// profile, as StageProvidersForPublish takes it. The Network Extension placement is assumed
// for the packet-tunnel profiles because that is where a deviation is decided, matching the
// publish path's own reasoning.
//
// The report is a value, not an error: a configuration with nothing to report answers with an
// empty list. Callers that cannot tell "no deviations" from "not asked" report silence as
// health, which is the failure the runtime endpoint's own comment names.
func ConfigDeviationsJSON(configContent string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, bridgeSafeError(err)
	}
	deviations, err := collectConfigDeviations(configContent, runtimePolicyFor(profile, true))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: collect config deviations: %w", err))
	}
	// document names the text this report is about, the same two numbers the runtime
	// endpoint serves, so a client can run one describes(text) over both kinds of
	// report. The macOS lane's first reading of "no document on the offline report" was that
	// the core did not send it at all; it had only ever been on the runtime envelope.
	sum := sha256.Sum256([]byte(configContent))
	payload := struct {
		SchemaVersion int                       `json:"schemaVersion"`
		Document      deviationDocumentIdentity `json:"document"`
		Deviations    []configDeviation         `json:"deviations"`
	}{configDeviationSchemaVersion, deviationDocumentIdentity{Bytes: len(configContent), SHA256: hex.EncodeToString(sum[:])}, deviations}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode config deviations: %w", err))
	}
	return WrapString(string(encoded)), nil
}
