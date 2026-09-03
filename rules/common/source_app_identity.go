package common

import (
	"errors"
	"strings"

	C "github.com/TokenPLS/Hako/constant"
)

const (
	maximumSourceAppSigningIdentifierBytes = 1024
	maximumSourceAppTeamIdentifierBytes    = 256
)

// SourceAppIdentity matches code-signing identity extracted atomically from
// the Apple flow audit token. These fields are deliberately separate from the
// executable name/path so a process cannot impersonate a signing rule merely
// by choosing its filename.
type SourceAppIdentity struct {
	Base
	pattern  string
	adapter  string
	ruleType C.RuleType
}

func NewSourceAppIdentity(
	pattern string,
	adapter string,
	ruleType C.RuleType,
) (*SourceAppIdentity, error) {
	limit := 0
	switch ruleType {
	case C.SourceAppSigningID:
		limit = maximumSourceAppSigningIdentifierBytes
	case C.SourceAppTeamID:
		limit = maximumSourceAppTeamIdentifierBytes
	default:
		return nil, errors.New("unsupported source-app identity rule type")
	}
	if pattern == "" || len(pattern) > limit || strings.ContainsRune(pattern, 0) {
		return nil, errPayload
	}
	return &SourceAppIdentity{
		pattern:  pattern,
		adapter:  adapter,
		ruleType: ruleType,
	}, nil
}

func (rule *SourceAppIdentity) RuleType() C.RuleType { return rule.ruleType }

func (rule *SourceAppIdentity) Adapter() string { return rule.adapter }

func (rule *SourceAppIdentity) Payload() string { return rule.pattern }

func (rule *SourceAppIdentity) Match(
	metadata *C.Metadata,
	helper C.RuleMatchHelper,
) (bool, string) {
	if !metadata.SourceIdentityKnown && helper.FindProcess != nil {
		helper.FindProcess()
	}
	var actual string
	switch rule.ruleType {
	case C.SourceAppSigningID:
		actual = metadata.SourceAppSigningIdentifier
	case C.SourceAppTeamID:
		actual = metadata.SourceAppTeamIdentifier
	default:
		return false, ""
	}
	if actual == rule.pattern {
		return true, rule.adapter
	}
	return false, ""
}

var _ C.Rule = (*SourceAppIdentity)(nil)
