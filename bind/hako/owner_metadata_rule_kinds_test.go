package hako

// The ten kinds, in the order the matrix lists them. Shared with unresolvableKindsFor so the
// Markdown and the JSON cannot name different sets.
var ownerMetadataRuleKinds = []string{
	"PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
	"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD",
	"UID", "IN-USER", "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID",
}
