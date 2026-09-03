package hako

import (
	"fmt"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/log"
)

// StageProvidersForPublish stages a configuration's file-backed providers from
// the process that already holds their bytes.
//
// The App downloads every provider a subscription names -- the Network
// Extension is not allowed to -- and then the extension read and
// decoded all of them again at tunnel start: 413ms of an 865ms cold start on a
// fifty-six provider subscription, inside a fifty-megabyte budget, with the
// reader watching a spinner. Nothing in that work needs the extension. It is a
// pure function of the published bytes, the definition's schema fields and the
// runtime policy, and the App is holding all three at the moment it finishes
// downloading, where the reader is already waiting on the network.
//
// Calling this after publishing a revision leaves the staged product and its
// manifest where the extension looks, so the extension's own staging pass finds
// every entry already answered. The distinction between a cold start and a warm
// one disappears: the first connection after switching subscriptions costs what
// the hundredth costs.
//
// This is an accelerator, never a requirement. The extension keeps its own
// staging path unchanged, so a manifest that is missing, stale, or written for
// a different core simply costs today's time instead of failing.
//
// targetProfile names the profile the EXTENSION will run under, not this
// process. It has to: three policy fields turn on whether the caller is inside
// a Network Extension -- networkExtension, requirePacketTunnelDNS,
// repairPacketTunnelDNS -- so staging for "whatever process I am" would
// fingerprint differently from the extension and miss every entry it wrote.
// Accepts the same values as SetupOptions.RuntimeProfile.
// compileRuleSets asks this publish to also compile rule sets to MRS. The
// caller passes a FACT — whether this process is a foregrounded App — and the
// decision lives here: compiling peaks in the hundreds of megabytes, which a
// foreground App survives and a backgrounded one has never been measured
// surviving. False stages exactly as before; a set nobody compiled is absent
// from the verdict fields and rides as text, which is the not-yet-compiled
// state, distinct by construction from notCompilable.
func StageProvidersForPublish(configContent string, targetProfile string, compileRuleSets bool) error {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return bridgeSafeError(err)
	}
	if err := validateConfigurationInput(configContent); err != nil {
		return bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	// Same canonicalization the start path runs, for the same reason and before
	// the same readers: a publish that skipped a `Type: file` definition would
	// stage nothing for it, and the extension would then read the reader's
	// unsanitized file directly.
	canonicalizeProviderDefinitionKeys(raw)
	// The extension always runs its providers under the Network Extension, so
	// that is the policy whose product it will look for.
	policy := runtimePolicyFor(profile, true)
	// normalizeRawConfigForApple runs first for the same reason it does on the
	// start path: it is what strips the surfaces a provider definition may name
	// and cannot use here, and staging must see the definitions the core will.
	normalizeRawConfigForApple(raw, policy)
	runtime, err := stageProviderRuntime(raw, policy, compileRuleSets)
	if err != nil {
		return bridgeSafeError(err)
	}
	verdicts := providerVerdictCounts{}
	if runtime != nil {
		verdicts = runtime.verdicts
		// Release this process's references. The staged directory stays on
		// disk -- it is the whole point.
		runtime.close()
	}
	// Where the products landed and what the verdicts were, in one line. A
	// staging tree written under an unexpected home directory once took a
	// night to find; this line makes the destination the first thing the log
	// answers, even when nothing was file-backed.
	log.Infoln("[Apple] provider publish staged into %s: compiled=%d notCompilable=%d keptSource=%d",
		stagedProviderParentDirectory(), verdicts.compiled, verdicts.notCompilable, verdicts.keptSource)
	return nil
}

// DiscardPublishedProviderStaging forgets a publish without touching the
// published sources.
//
// It exists for the case the staging cache cannot detect on its own: a
// configuration the reader deleted, or a publish that turned out to describe a
// revision that will never be activated. Staging invalidates itself when a
// source's bytes, schema or policy change, so this is not needed for an
// ordinary edit.
//
// Failing to discard costs disk, never correctness: a stale entry whose source
// no longer matches is rejected at the next start regardless.
func DiscardPublishedProviderStaging() {
	parent := stagedProviderParentDirectory()
	manifest := &stagedProviderManifest{Entries: map[string]stagedProviderRecord{}}
	saveStagedProviderManifest(parent, manifest)
	sweepStagedProviderRuntime(parent, stagedProviderDirectory(), map[string]struct{}{})
	log.Infoln("[Apple] published provider staging discarded; the next start will stage from source")
}
