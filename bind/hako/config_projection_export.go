package hako

// ConfigProjectionJSON is the projection door for documents that have no
// revision: unsaved drafts, pasted fragments, synthetic single-node files.
// It IS the handle route -- open, project, close -- so a second producer that
// could disagree does not exist by construction.
//
// It lives in its own file because it is release surface: a change to what
// this package exports should be visible at a glance in review, separate from
// the internal producer it delegates to.
func ConfigProjectionJSON(configContent, kind, packagesJSON string) (*StringBox, error) {
	doc, err := NewConfigDocument(configContent)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	defer doc.Close()
	bridgedValue0, bridgedErr := doc.ProjectionJSON(kind, packagesJSON)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}
