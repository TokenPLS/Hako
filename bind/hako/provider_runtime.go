package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
)

const providerRuntimeDirectoryName = "provider-runtime"
const providerSideUpdateSafeField = "x-hako-side-update-safe"

type providerRuntimeEntry struct {
	behavior       string
	format         string
	compiled       bool
	sideUpdateSafe bool
	runtimePath    string
}

// providerVerdictCounts totals the staged tree's compile verdicts in the
// locked wire vocabulary: compiled | notCompilable | keptSource. An entry
// with no verdict (a proxy provider, or a rule set no publish has compiled
// yet) is in none of the three.
type providerVerdictCounts struct {
	compiled      int
	notCompilable int
	keptSource    int
}

type providerRuntime struct {
	directory string
	entries   map[string]providerRuntimeEntry
	policy    appleRuntimePolicy
	verdicts  providerVerdictCounts
}

func providerRuntimeKey(kind, name string) string {
	return kind + "\x00" + name
}

// stagingCost itemises where a cold staging pass spends its time. The
// aggregate mark said 410ms for fifty-seven providers and could not say
// which kind of provider that was: an MRS rule set is zstd-decompressed in
// full merely to prove it is a readable MRS (mrs_validation.go), while a
// classical .list is scanned line by line to strip metadata rules, and a
// cache hit is two lstats. Those are three different costs and only one of
// them is worth attacking.
type stagingCost struct {
	hitCount       int
	hitNanos       int64
	readCount      int
	readNanos      int64
	readBytes      int64
	mrsCount       int
	mrsNanos       int64
	classicalCount int
	classicalNanos int64
	proxyCount     int
	proxyNanos     int64
	commitCount    int
	commitNanos    int64
	compileCount   int
	compileNanos   int64
}

func (c *stagingCost) line() string {
	ms := func(n int64) float64 { return float64(n) / 1e6 }
	return fmt.Sprintf(
		"stage-cost hit=%d/%.0fms read=%d/%.0fms/%.1fMiB mrs=%d/%.0fms classical=%d/%.0fms proxy=%d/%.0fms commit=%d/%.0fms",
		c.hitCount, ms(c.hitNanos),
		c.readCount, ms(c.readNanos), float64(c.readBytes)/(1<<20),
		c.mrsCount, ms(c.mrsNanos),
		c.classicalCount, ms(c.classicalNanos),
		c.proxyCount, ms(c.proxyNanos),
		c.commitCount, ms(c.commitNanos)) + func() string {
		if c.compileCount == 0 {
			return ""
		}
		return fmt.Sprintf(" compile=%d/%.0fms", c.compileCount, ms(c.compileNanos))
	}()
}

const providerRuntimeStagedDirectoryName = "staged"

// Both the publish entry and the start path resolve these the same way, so the
// two processes write and read the same tree.
func stagedProviderParentDirectory() string {
	return filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
}

func stagedProviderDirectory() string {
	return filepath.Join(stagedProviderParentDirectory(), providerRuntimeStagedDirectoryName)
}

const providerRuntimeManifestName = "staged-manifest.json"

// providerStagingLogicVersion names the staging algorithm, not the data: bump
// it whenever sanitize/prepare could emit different bytes or a different
// verdict for identical inputs, or every cached product silently keeps the
// retired behavior. The core version in the manifest does not cover this --
// C.Version moves with the vendored mihomo, not with this file.
//
// 3: the keptSource verdict — a compile refusal stages the source online
// instead of empty on profiles without compiledRuleSetsOnly.
// 4: records carry the staged product's digest; a hit verifies it rather than
// trusting the size alone.
const providerStagingLogicVersion = 4

type stagedProviderNoop struct {
	Kind   string `json:"kind,omitempty"`
	Field  string `json:"field,omitempty"`
	Index  int    `json:"index"`
	Reason int    `json:"reason,omitempty"`
}

type stagedProviderRecord struct {
	Source         string               `json:"source"`
	SourceSize     int64                `json:"sourceSize"`
	SourceMtimeNS  int64                `json:"sourceMtimeNS"`
	SourceInode    uint64               `json:"sourceInode"`
	Behavior       string               `json:"behavior,omitempty"`
	Format         string               `json:"format,omitempty"`
	SideUpdateSafe bool                 `json:"sideUpdateSafe,omitempty"`
	File           string               `json:"file"`
	StagedSize     int64                `json:"stagedSize"`
	EgressNoops    []stagedProviderNoop `json:"egressNoops,omitempty"`
	MetadataNoops  []stagedProviderNoop `json:"metadataNoops,omitempty"`
	UnreadableWarn string               `json:"unreadableWarn,omitempty"`
	// The MRS compile verdict. compiled is written only by a publish that
	// compiled (the App process; the extension never compiles), but
	// notCompilable can also be written by an extension restage on a
	// compiled-only profile: the refusal judgement is a line scan, and it must
	// survive a manifest invalidation or the empty-set ruling silently becomes
	// a text load. Absent means NOT YET COMPILED — the set rides as text
	// exactly as before any of this existed — and absent is the only spelling
	// of that state; an empty string is not a verdict.
	// Behavior/Format above keep the DEFINITION's original values (the cache
	// hit compares against the configuration), so the artifact's actual
	// strategy travels separately in CompiledBehavior.
	CompileVerdict   string `json:"compileVerdict,omitempty"`
	CompiledBehavior string `json:"compiledBehavior,omitempty"`
	CompileReason    string `json:"compileReason,omitempty"`
	// ContentSHA256 is what the staged file contained when staging produced it.
	// A cache hit serves that file to the core without re-running sanitize,
	// strip or compile, so before this field the only thing standing between a
	// rewritten staged file and the running core was a size comparison -- and
	// an equal-length rewrite passes one. The bytes are already in memory at
	// staging time, so recording the digest costs a hash of what was just
	// written. Absent on records written by an older core: those miss and
	// restage, which is the safe direction.
	ContentSHA256 string `json:"contentSHA256,omitempty"`
}

// compiledBehaviorIsKnown reports whether a manifest's recorded compiled
// behavior is one this core can hand back to the definition. The value is
// rewritten into the provider definition on a cache hit, and an unknown one
// fails ParseRawConfig -- which fails the whole start, on every start, because
// the manifest outlives the process.
func compiledBehaviorIsKnown(behavior string) bool {
	switch behavior {
	case "domain", "ipcidr", "classical":
		return true
	default:
		return false
	}
}

// maximumStagedManifestBytes bounds the manifest read. It is a JSON control
// file listing a few dozen providers, not a payload; reading it unbounded let
// one oversized file (or a symlink to one) end every start inside a 50 MiB
// process.
const maximumStagedManifestBytes = 4 << 20

func stagedFileDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// requireRealDirectoryOrAbsent reports an error when path exists but is not a
// real directory -- a symlink included. Absent is fine: the caller is about to
// create it. Lstat, not Stat, because a symlink to a directory is exactly the
// case this exists to catch.
func requireRealDirectoryOrAbsent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return errors.New("path exists and is not a directory")
	}
	return nil
}

// SideUpdateDeferredPrefix begins every side-update error that means "not
// failed, applies later" — today, the refusal for a compiled rule set. The
// client distinguishes a deferral from a failure by this prefix (exported so
// neither side hand-copies the words), because a background refresh that
// counts a deferral as a failure teaches BGTaskScheduler to starve the app.
const SideUpdateDeferredPrefix = "hako: side update deferred: "

const (
	compileVerdictCompiled      = "compiled"
	compileVerdictNotCompilable = "notCompilable"
	compileVerdictKeptSource    = "keptSource"
)

type stagedProviderManifest struct {
	Schema  int                             `json:"schema"`
	Logic   int                             `json:"logic"`
	Core    string                          `json:"core"`
	Policy  string                          `json:"policy"`
	Entries map[string]stagedProviderRecord `json:"entries"`
}

func stagedPolicyFingerprint(policy appleRuntimePolicy) string {
	// Every field is a value type, so this is stable across runs; a policy
	// that grows a field changes the fingerprint and restages everything,
	// which is the correct default for an input nobody listed here.
	return fmt.Sprintf("%+v", policy)
}

func newStagedProviderManifest(policy appleRuntimePolicy) *stagedProviderManifest {
	return &stagedProviderManifest{
		Schema:  1,
		Logic:   providerStagingLogicVersion,
		Core:    C.Version,
		Policy:  stagedPolicyFingerprint(policy),
		Entries: map[string]stagedProviderRecord{},
	}
}

func loadStagedProviderManifest(parent string, policy appleRuntimePolicy) *stagedProviderManifest {
	empty := &stagedProviderManifest{Entries: map[string]stagedProviderRecord{}}
	payload, err := readBoundedRegularFile(
		filepath.Join(parent, providerRuntimeManifestName),
		maximumStagedManifestBytes, "provider staging manifest")
	if err != nil {
		return empty
	}
	manifest := &stagedProviderManifest{}
	if json.Unmarshal(payload, manifest) != nil || manifest.Entries == nil {
		return empty
	}
	if manifest.Schema != 1 ||
		manifest.Logic != providerStagingLogicVersion ||
		manifest.Core != C.Version ||
		manifest.Policy != stagedPolicyFingerprint(policy) {
		return empty
	}
	return manifest
}

// saveStagedProviderManifest is best-effort: a manifest that fails to write
// costs the next start a rebuild, not correctness, so staging never fails
// over it.
func saveStagedProviderManifest(parent string, manifest *stagedProviderManifest) {
	payload, err := json.Marshal(manifest)
	if err == nil {
		err = writeRuntimeProviderFile(
			filepath.Join(parent, providerRuntimeManifestName), payload)
	}
	if err != nil {
		log.Warnln("[iOS] provider staging manifest not recorded (%v); the next start restages from source", err)
	}
}

type providerSourceIdentity struct {
	size    int64
	mtimeNS int64
	inode   uint64
}

func stagedSourceIdentity(path string) (providerSourceIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return providerSourceIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return providerSourceIdentity{}, errors.New("published provider is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return providerSourceIdentity{}, errors.New("published provider carries no inode identity")
	}
	return providerSourceIdentity{
		size:    info.Size(),
		mtimeNS: info.ModTime().UnixNano(),
		inode:   stat.Ino,
	}, nil
}

func stagedProviderRecordMatches(record stagedProviderRecord, sourcePath, behavior, format string) bool {
	if record.Source != sourcePath || record.Behavior != behavior || record.Format != format {
		return false
	}
	identity, err := stagedSourceIdentity(sourcePath)
	if err != nil {
		return false
	}
	return identity.size == record.SourceSize &&
		identity.mtimeNS == record.SourceMtimeNS &&
		identity.inode == record.SourceInode
}

// stagedFileMatches decides whether the staged product on disk is still the
// one staging produced. The size is the cheap gate; the digest is the one that
// holds, because a rewrite that keeps the length is invisible to the size and
// the served file never passes through sanitize/strip/compile again.
//
// A record with no digest predates this check and is treated as a miss: the
// entry restages from the published source, which costs one pass and cannot
// serve someone else's bytes.
func stagedFileMatches(path string, record stagedProviderRecord) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.StagedSize {
		return false
	}
	if record.ContentSHA256 == "" {
		return false
	}
	if record.StagedSize < 0 || record.StagedSize > int64(maximumProviderResourceBytes) {
		return false
	}
	payload, err := os.ReadFile(path)
	if err != nil || int64(len(payload)) != record.StagedSize {
		return false
	}
	return stagedFileDigest(payload) == record.ContentSHA256
}

// replayStagedProviderWarnings re-emits the verdict the original staging
// logged, so a start served from the cache warns exactly as loudly as the
// one that did the work.
func replayStagedProviderWarnings(name string, record stagedProviderRecord) {
	if record.CompileVerdict == compileVerdictNotCompilable {
		// A cached start must warn exactly as loudly as the one that did the work:
		// this set rides empty, and silence here is indistinguishable from a set
		// that works.
		log.Warnln("[iOS] rule provider %q is not compilable and rides empty: %s", name, record.CompileReason)
	}
	if record.CompileVerdict == compileVerdictKeptSource {
		logKeptSourceRuleProvider(name, record.CompileReason)
	}
	if record.UnreadableWarn != "" {
		warnUnreadableRuleProvider(name, errors.New(record.UnreadableWarn))
	}
	if len(record.EgressNoops) > 0 {
		stripped := make([]providerEgressNoop, 0, len(record.EgressNoops))
		for _, noop := range record.EgressNoops {
			stripped = append(stripped, providerEgressNoop{field: noop.Field, index: noop.Index})
		}
		warnProviderEgressNoops(name, stripped)
	}
	if len(record.MetadataNoops) > 0 {
		stripped := make([]providerMetadataNoop, 0, len(record.MetadataNoops))
		for _, noop := range record.MetadataNoops {
			stripped = append(stripped, providerMetadataNoop{
				kind: noop.Kind, index: noop.Index,
				reason: providerNoopReason(noop.Reason),
			})
		}
		warnProviderMetadataNoops(name, stripped)
	}
}

func encodeEgressNoops(stripped []providerEgressNoop) []stagedProviderNoop {
	if len(stripped) == 0 {
		return nil
	}
	encoded := make([]stagedProviderNoop, 0, len(stripped))
	for _, noop := range stripped {
		encoded = append(encoded, stagedProviderNoop{Field: noop.field, Index: noop.index})
	}
	return encoded
}

func encodeMetadataNoops(stripped []providerMetadataNoop) []stagedProviderNoop {
	if len(stripped) == 0 {
		return nil
	}
	encoded := make([]stagedProviderNoop, 0, len(stripped))
	for _, noop := range stripped {
		encoded = append(encoded, stagedProviderNoop{
			Kind: noop.kind, Index: noop.index, Reason: int(noop.reason),
		})
	}
	return encoded
}

// invalidateStagedProviderRecord forgets one provider's staged product. A
// side update has just replaced the staged bytes while the tunnel runs, so
// they no longer equal what staging would produce from the published source;
// the next start must rebuild from that source -- which is exactly the
// restart semantics the per-start rebuild used to provide.
func invalidateStagedProviderRecord(kind, name string) {
	parent := filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
	payload, err := readBoundedRegularFile(
		filepath.Join(parent, providerRuntimeManifestName),
		maximumStagedManifestBytes, "provider staging manifest")
	if err != nil {
		return
	}
	manifest := &stagedProviderManifest{}
	if json.Unmarshal(payload, manifest) != nil || manifest.Entries == nil {
		return
	}
	key := providerRuntimeKey(kind, name)
	if _, exists := manifest.Entries[key]; !exists {
		return
	}
	delete(manifest.Entries, key)
	saveStagedProviderManifest(parent, manifest)
}

// sweepStagedProviderRuntime clears what the configuration dropped and the
// retired per-start directories a jetsam kill used to strand. During a live
// Reload the outgoing core may still hold a swept file's descriptor; the
// unlinked inode stays readable, and a path-based refresh in that window
// fails recoverably, so immediate sweeping is the right trade.
func sweepStagedProviderRuntime(parent, stagedDirectory string, referenced map[string]struct{}) {
	if entries, err := os.ReadDir(parent); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if name == providerRuntimeStagedDirectoryName || name == providerRuntimeManifestName {
				continue
			}
			_ = os.RemoveAll(filepath.Join(parent, name))
		}
	}
	files, err := os.ReadDir(stagedDirectory)
	if err != nil {
		return
	}
	for _, file := range files {
		if _, keep := referenced[file.Name()]; keep {
			continue
		}
		_ = os.Remove(filepath.Join(stagedDirectory, file.Name()))
	}
}

// stageProviderRuntime redirects every file-backed provider to a private
// shadow before mihomo constructs its provider objects. The shadow starts as
// a hard link to the immutable published revision; an update replaces only
// the shadow inode, giving the Core copy-on-write semantics without a second
// initial copy or a mutation of App-owned source data.
//
// The shadow directory is persistent, not per-start. Staging is a pure
// function of the published bytes, the definition's schema fields and the
// runtime policy -- and its inputs are immutable revision files, so the
// 2026-08-05 itemised startup trace showed every tunnel start re-reading and
// re-decoding fifty-six unchanged provider files for 347 of its 890ms. The
// manifest beside the shadow records each product's inputs; a start whose
// inputs still match serves the previous product for the price of two
// lstats, and re-emits the recorded warnings so a cached start is exactly as
// loud as the one that did the work.
func stageProviderRuntime(raw *config.RawConfig, policy appleRuntimePolicy, compileRuleSets bool) (*providerRuntime, error) {
	definitions := []struct {
		kind      string
		providers map[string]map[string]any
	}{{kind: "proxy", providers: raw.ProxyProvider}, {kind: "rule", providers: raw.RuleProvider}}

	parent := filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
	stagedDirectory := filepath.Join(parent, providerRuntimeStagedDirectoryName)
	var runtime *providerRuntime
	var manifest, next *stagedProviderManifest
	referenced := map[string]struct{}{}
	var cost stagingCost
	cleanupOnError := func(err error) (*providerRuntime, error) {
		if runtime != nil {
			runtime.close()
		}
		return nil, err
	}
	for _, namespace := range definitions {
		names := make([]string, 0, len(namespace.providers))
		for name := range namespace.providers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			definition := namespace.providers[name]
			typeName, _ := definition["type"].(string)
			if typeName != "file" {
				continue
			}
			sourceValue, _ := definition["path"].(string)
			if strings.TrimSpace(sourceValue) == "" {
				return cleanupOnError(fmt.Errorf("hako: %s provider path is empty", namespace.kind))
			}
			sourcePath := C.Path.Resolve(sourceValue)
			if pathInsideDirectory(sourcePath, parent) {
				return cleanupOnError(fmt.Errorf("hako: %s provider source points into runtime storage", namespace.kind))
			}
			// The path is subscription-authored text and upstream's own guard is
			// a no-op in this build (see providerSourceContained). The error
			// names the provider, never the path: the path is what the attacker
			// is probing with, and this text reaches the log.
			if !providerSourceContained(sourcePath, C.Path.HomeDir()) {
				return cleanupOnError(fmt.Errorf(
					"hako: %s provider %q names a path outside this app's container and cannot be read",
					namespace.kind, name))
			}
			if runtime == nil {
				// A symlink planted at the runtime root would redirect every
				// staged write, and turn the sweep below into an indiscriminate
				// RemoveAll of a directory that is not ours. MkdirAll and Chmod
				// both follow links, so this check comes first and uses Lstat.
				if err := requireRealDirectoryOrAbsent(parent); err != nil {
					return nil, fmt.Errorf("hako: provider runtime directory: %w", err)
				}
				if err := os.MkdirAll(stagedDirectory, 0o700); err != nil {
					return nil, fmt.Errorf("hako: create provider runtime directory: %w", err)
				}
				if err := requireRealDirectoryOrAbsent(stagedDirectory); err != nil {
					return nil, fmt.Errorf("hako: provider runtime directory: %w", err)
				}
				if err := os.Chmod(stagedDirectory, 0o700); err != nil {
					return nil, fmt.Errorf("hako: protect provider runtime directory: %w", err)
				}
				runtime = &providerRuntime{
					directory: stagedDirectory,
					entries:   make(map[string]providerRuntimeEntry),
					policy:    policy,
				}
				manifest = loadStagedProviderManifest(parent, policy)
				next = newStagedProviderManifest(policy)
			}
			behavior, _ := definition["behavior"].(string)
			format, _ := definition["format"].(string)
			fileName := providerRuntimeFileName(namespace.kind, name)
			runtimePath := filepath.Join(stagedDirectory, fileName)
			key := providerRuntimeKey(namespace.kind, name)
			sideUpdateSafe := namespace.kind == "proxy"
			if namespace.kind == "rule" {
				sideUpdateSafe, _ = definition[providerSideUpdateSafeField].(bool)
			}

			hitStart := time.Now()
			if record, hit := manifest.Entries[key]; hit &&
				stagedProviderRecordMatches(record, sourcePath, behavior, format) &&
				stagedFileMatches(runtimePath, record) &&
				// A publish that compiles must not be served yesterday's text
				// staging: a rule record with no verdict misses, restages and
				// gets its verdict. The extension (compileRuleSets false)
				// keeps hitting it, which is exactly the not-yet-compiled state.
				!(compileRuleSets && namespace.kind == "rule" &&
					record.CompileVerdict == "" && record.UnreadableWarn == "") {
				cost.hitCount++
				cost.hitNanos += time.Since(hitStart).Nanoseconds()
				replayStagedProviderWarnings(name, record)
				// sideUpdateSafe belongs to the configuration, not the file:
				// take the current definition's answer, not the recorded one.
				record.SideUpdateSafe = sideUpdateSafe
				entryBehavior, entryFormat := behavior, format
				if record.CompileVerdict == compileVerdictCompiled &&
					!compiledBehaviorIsKnown(record.CompiledBehavior) {
					// The manifest claims an artifact but names a strategy this
					// core cannot parse. Handing it to the definition fails
					// ParseRawConfig and therefore the whole start, on every
					// start. Treat the record as absent and rebuild.
					log.Warnln("[Apple] staged rule provider %q records an unknown compiled behavior; restaging from source", name)
					record = stagedProviderRecord{}
				}
				if record.CompileVerdict == compileVerdictCompiled {
					// The three values that must agree are rewritten by the one
					// function both processes run — the reuse path included, or
					// the extension would read MRS bytes under a text strategy.
					definition["format"] = "mrs"
					definition["behavior"] = record.CompiledBehavior
					entryBehavior, entryFormat = record.CompiledBehavior, "mrs"
				}
				next.Entries[key] = record
				referenced[fileName] = struct{}{}
				runtime.entries[key] = providerRuntimeEntry{
					behavior: entryBehavior, format: entryFormat, sideUpdateSafe: sideUpdateSafe,
					compiled:    record.CompileVerdict == compileVerdictCompiled,
					runtimePath: runtimePath,
				}
				definition["path"] = runtimePath
				continue
			}

			// The identity is taken before the bytes are read: an edit that
			// lands between the two makes the next start's comparison miss
			// and restage, instead of being trusted forever.
			identity, err := stagedSourceIdentity(sourcePath)
			if err != nil {
				return cleanupOnError(fmt.Errorf("hako: stage %s provider runtime: %w", namespace.kind, err))
			}
			record := stagedProviderRecord{
				Source:     sourcePath,
				SourceSize: identity.size, SourceMtimeNS: identity.mtimeNS, SourceInode: identity.inode,
				Behavior: behavior, Format: format, SideUpdateSafe: sideUpdateSafe,
				File: fileName,
			}
			commitStart := time.Now()
			if namespace.kind == "rule" {
				// Schema before content, because upstream is fatal on one and
				// tolerant of the other. An unparseable behavior/format STRING
				// fails inside ParseRuleProvider (rules/provider/parse.go:34-41)
				// during config.ParseRawConfig, where parseRuleProviders stops
				// the whole load (config/config.go:687-690, 1014-1027) -- these
				// definition fields are staged untouched, so tolerating the typo
				// here would not make the config start; it would only trade this
				// contextual error for mihomo's bare one, after logging a false
				// "still starts". Only defects in the file's CONTENT are on
				// upstream's warn-and-continue path below.
				if err := ruleProviderSchemaError(behavior, format); err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
				}
				readStart := time.Now()
				// A zero-byte published rule set is the App's deliberate
				// staging of a failed download (the start-first ruling): skip
				// the bounded read, whose size guard would kill the whole
				// start with "size is invalid" before the warn-and-continue
				// tolerance below ever ran, and hand prepare the empty
				// payload instead — it takes the same non-fatal path as
				// unreadable content and the rule set matches nothing.
				var payload []byte
				if identity.size > 0 {
					payload, err = readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
				}
				cost.readCount++
				cost.readNanos += time.Since(readStart).Nanoseconds()
				cost.readBytes += int64(len(payload))
				if err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
				}
				prepareStart := time.Now()
				prepared, stripped, prepareErr := prepareRuleProviderRuntimePayload(behavior, format, payload, policy)
				// The two rule paths cost nothing alike: MRS is a full zstd
				// decompression to prove readability, classical is a line scan.
				if strings.EqualFold(strings.TrimSpace(format), "mrs") {
					cost.mrsCount++
					cost.mrsNanos += time.Since(prepareStart).Nanoseconds()
				} else {
					cost.classicalCount++
					cost.classicalNanos += time.Since(prepareStart).Nanoseconds()
				}
				if compileRuleSets && prepareErr == nil &&
					strings.EqualFold(strings.TrimSpace(format), "mrs") {
					// Already the compact form: record it, so the hit gate stops
					// forcing a full restage on every compile-enabled publish.
					record.CompileVerdict = compileVerdictCompiled
					record.CompiledBehavior = strings.ToLower(strings.TrimSpace(behavior))
				}
				extensionRefusal := ""
				if !compileRuleSets && policy.compiledRuleSetsOnly && prepareErr == nil &&
					identity.size > 0 && !strings.EqualFold(strings.TrimSpace(format), "mrs") {
					// Judge what the compiler would see: stripping runs first
					// there too, and a set whose unstorable rules are exactly
					// the stripped ones compiles clean after preparation.
					judged := payload
					if len(stripped) > 0 {
						judged = prepared
					}
					extensionRefusal = ruleProviderCompileRefusal(judged, behavior, format)
				}
				if compileRuleSets && prepareErr == nil && identity.size > 0 &&
					!strings.EqualFold(strings.TrimSpace(format), "mrs") {
					// The publish process compiles; the artifact becomes the
					// staged runtime file itself, and the definition's three
					// values move together. A set the compiler refuses is
					// staged EMPTY instead of stripped: RULE-SET references can
					// hide inside AND()/OR()/NOT() and sub-rules, where a
					// removed provider is a fatal dangling name, while an empty
					// set matches nothing — the zero-byte deliberate-staging
					// precedent, reused. Either way the start is never blocked.
					content := payload
					if len(stripped) > 0 {
						content = prepared
					}
					compileStart := time.Now()
					compilation := compileRuleProviderPayload(content, behavior, format)
					cost.compileCount++
					cost.compileNanos += time.Since(compileStart).Nanoseconds()
					if compilation.Reason != "" && policy.compiledRuleSetsOnly {
						if err := writeRuntimeProviderFile(runtimePath, nil); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.CompileVerdict = compileVerdictNotCompilable
						record.CompileReason = compilation.Reason
						log.Warnln("[iOS] rule provider %q is not compilable and rides empty: %s",
							name, compilation.Reason)
					} else if compilation.Reason != "" {
						// A profile without the memory ceiling keeps the source
						// online and pays the parse, exactly as upstream does:
						// the prepared copy when stripping preceded, the
						// published bytes verbatim otherwise. The verdict still
						// lands in the manifest — with the same reason a
						// refusal records — so a hit is a hit and the account
						// stays readable.
						if len(stripped) > 0 {
							if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
								return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
							}
							record.MetadataNoops = encodeMetadataNoops(stripped)
							warnProviderMetadataNoops(name, stripped)
						} else if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.CompileVerdict = compileVerdictKeptSource
						record.CompileReason = compilation.Reason
						logKeptSourceRuleProvider(name, compilation.Reason)
					} else {
						if err := writeRuntimeProviderFile(runtimePath, compilation.artifact); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.CompileVerdict = compileVerdictCompiled
						record.CompiledBehavior = compilation.Behavior
						definition["format"] = "mrs"
						definition["behavior"] = compilation.Behavior
						if len(stripped) > 0 {
							record.MetadataNoops = encodeMetadataNoops(stripped)
							warnProviderMetadataNoops(name, stripped)
						}
						log.Infoln("[iOS] rule provider %q compiled to MRS: %d rules, %d bytes",
							name, compilation.Rules, len(compilation.artifact))
					}
				} else if extensionRefusal != "" {
					// The extension never compiles, but the REFUSAL judgement is
					// a line scan it can afford -- and it must run here, because
					// a manifest invalidation (a logic bump, a core upgrade)
					// voids the recorded verdict while the client republishes
					// only on activation. Without this, the compiled-only
					// profile's empty-set safety ruling silently became a text
					// load of the refused source, and a jetsam would restart
					// into the same state. Same scan as the compiler, so the
					// two judgements cannot drift.
					if err := writeRuntimeProviderFile(runtimePath, nil); err != nil {
						return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
					}
					record.CompileVerdict = compileVerdictNotCompilable
					record.CompileReason = extensionRefusal
					log.Warnln("[iOS] rule provider %q is not compilable and rides empty: %s",
						name, record.CompileReason)
				} else {
					switch {
					case prepareErr != nil:
						// A rule set this core cannot read is not a reason to refuse the
						// configuration. Upstream loads providers with
						// hub/executor/executor.go:318-338, where a failed Initial() produces
						// `log.Errorln("initial rule provider %s error: %v")` and nothing
						// else -- the config starts and that one rule set is empty. Nor is
						// the failure platform-relevant: an unreadable rule set costs no
						// memory, spawns nothing, downloads nothing (it is already a staged
						// file provider) and leaves no sandbox. Both questions answer
						// no, so this may not be fatal.
						//
						// It was, and it cost a real user 26 working rule sets: an OpenClash
						// export with 27 rule providers had exactly one pointing at a GitHub
						// /blob/ HTML page while declaring format: mrs. The magic-number
						// error was correct and the whole profile died of it.
						//
						// The bytes are staged verbatim rather than replaced or dropped, so
						// what mihomo reads is what the user published and its own error
						// names a real cause. That is safe because ParseRuleProvider only
						// builds a FileVehicle (rules/provider/parse.go:50) and never reads
						// the file -- the read is Initial()'s, on the non-fatal path above.
						if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.UnreadableWarn = prepareErr.Error()
						warnUnreadableRuleProvider(name, prepareErr)
					case len(stripped) > 0:
						if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.MetadataNoops = encodeMetadataNoops(stripped)
						warnProviderMetadataNoops(name, stripped)
					default:
						if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
					}
				}
			} else {
				readStart := time.Now()
				payload, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
				cost.readCount++
				cost.readNanos += time.Since(readStart).Nanoseconds()
				cost.readBytes += int64(len(payload))
				if err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
				}
				proxyStart := time.Now()
				prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(format, payload, false)
				cost.proxyCount++
				cost.proxyNanos += time.Since(proxyStart).Nanoseconds()
				if err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
				}
				if len(stripped) > 0 {
					if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
						return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
					}
					record.EgressNoops = encodeEgressNoops(stripped)
					warnProviderEgressNoops(name, stripped)
				} else if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
				}
			}
			cost.commitCount++
			cost.commitNanos += time.Since(commitStart).Nanoseconds()
			stagedInfo, err := os.Lstat(runtimePath)
			if err != nil {
				return cleanupOnError(fmt.Errorf("hako: stage %s provider runtime: %w", namespace.kind, err))
			}
			record.StagedSize = stagedInfo.Size()
			// The digest of what actually landed, so a later start can tell
			// this product from one somebody rewrote. Read back rather than
			// hashed from the in-memory buffer on purpose: the file is what the
			// core will read, and the two differ on every path that hardlinks
			// the source instead of writing prepared bytes.
			if staged, readErr := os.ReadFile(runtimePath); readErr == nil {
				record.ContentSHA256 = stagedFileDigest(staged)
			}
			next.Entries[key] = record
			referenced[fileName] = struct{}{}
			entryBehavior, _ := definition["behavior"].(string)
			entryFormat, _ := definition["format"].(string)
			runtime.entries[key] = providerRuntimeEntry{
				behavior: entryBehavior, format: entryFormat, sideUpdateSafe: sideUpdateSafe,
				compiled:    record.CompileVerdict == compileVerdictCompiled,
				runtimePath: runtimePath,
			}
			definition["path"] = runtimePath
		}
	}
	if runtime != nil {
		for _, record := range next.Entries {
			switch record.CompileVerdict {
			case compileVerdictCompiled:
				runtime.verdicts.compiled++
			case compileVerdictNotCompilable:
				runtime.verdicts.notCompilable++
			case compileVerdictKeptSource:
				runtime.verdicts.keptSource++
			}
		}
		startupStage(cost.line())
		saveStagedProviderManifest(parent, next)
		sweepStagedProviderRuntime(parent, stagedDirectory, referenced)
	}
	stripProviderSideUpdateMetadata(raw)
	return runtime, nil
}

func stripProviderSideUpdateMetadata(raw *config.RawConfig) {
	for _, definition := range raw.RuleProvider {
		delete(definition, providerSideUpdateSafeField)
	}
}

func providerRuntimeFileName(kind, name string) string {
	digest := sha256.Sum256([]byte(providerRuntimeKey(kind, name)))
	return hex.EncodeToString(digest[:]) + ".provider"
}

func pathInsideDirectory(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && filepath.IsLocal(relative)
}

// providerSourceContained reports whether a provider's source path stays
// inside the container this process owns, resolving symlinks first.
//
// Upstream has this check -- C.Path.IsSafePath, called from
// rules/provider/parse.go and adapter/provider/parser.go -- but it opens with
// `if p.allowUnsafePath || features.CMFA { return true }` (constant/path.go),
// and every shipped Hako binary carries the cmfa tag by ruling
// (cmd/build_libbox/main.go:58). So in this build upstream's guard answers true
// for every path, including `../../../../etc/passwd`. Staging reads the file
// before upstream would look anyway, and rewrites the definition to the staged
// copy, so nothing downstream ever sees the original path either: if this
// function does not hold the line, nothing does.
//
// Symlinks are resolved because a lexical check waves through an in-container
// link that points out of it. A path whose parents do not exist yet cannot be
// resolved; the deepest existing ancestor is resolved instead, which is what
// the attack would have to subvert. Failure is refusal, not acceptance.
func providerSourceContained(sourcePath, home string) bool {
	if home == "" {
		return false
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		resolvedHome = filepath.Clean(home)
	}
	resolved, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		// The leaf may legitimately not exist yet (staging reports that with a
		// better error); resolve the deepest ancestor that does.
		directory, file := filepath.Split(sourcePath)
		resolvedDirectory, dirErr := filepath.EvalSymlinks(filepath.Clean(directory))
		if dirErr != nil {
			return false
		}
		resolved = filepath.Join(resolvedDirectory, file)
	}
	return pathInsideDirectory(resolved, resolvedHome)
}

func stageRuntimeProviderFile(sourcePath, runtimePath string) error {
	before, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat published provider: %w", err)
	}
	// No lower bound: a zero-byte published rule set is the App's deliberate
	// staging of a failed download (start-first ruling), staged verbatim so
	// the profile starts and that rule set matches nothing.
	if !before.Mode().IsRegular() || before.Size() > int64(maximumProviderResourceBytes) {
		return fmt.Errorf("published provider is not a bounded regular file")
	}
	// Linked to a temporary name and renamed over: the staged directory is
	// persistent now, so the destination may hold the previous product, and
	// link(2) refuses to replace.
	temporaryPath := runtimePath + ".staging"
	_ = os.Remove(temporaryPath)
	if err := os.Link(sourcePath, temporaryPath); err == nil {
		after, sourceErr := os.Lstat(sourcePath)
		shadow, shadowErr := os.Lstat(temporaryPath)
		if sourceErr == nil && shadowErr == nil && after.Mode().IsRegular() && shadow.Mode().IsRegular() &&
			os.SameFile(before, after) && os.SameFile(after, shadow) {
			if err := os.Rename(temporaryPath, runtimePath); err != nil {
				_ = os.Remove(temporaryPath)
				return err
			}
			return nil
		}
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("published provider changed while hard-linking")
	}

	if before.Size() == 0 {
		// readBoundedRegularFile refuses empty files; the deliberate empty
		// staging above still has to survive the copy fallback.
		return writeRuntimeProviderFile(runtimePath, nil)
	}
	payload, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
	if err != nil {
		return err
	}
	return writeRuntimeProviderFile(runtimePath, payload)
}

func writeRuntimeProviderFile(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".provider-update-")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// ruleProviderSchemaError reports whether the behavior/format STRINGS parse.
// It exists so staging can separate what upstream refuses at config load (these
// strings, via ParseRuleProvider) from what upstream tolerates per provider at
// Initial() (the file's content) -- the two halves of the staging switch above.
func ruleProviderSchemaError(behavior, format string) error {
	if _, err := P.ParseBehavior(behavior); err != nil {
		return fmt.Errorf("hako: provider behavior: %w", err)
	}
	if _, err := P.ParseRuleFormat(format); err != nil {
		return fmt.Errorf("hako: provider format: %w", err)
	}
	return nil
}

func prepareRuleProviderRuntimePayload(behavior, format string, payload []byte, policy appleRuntimePolicy) ([]byte, []providerMetadataNoop, error) {
	parsedBehavior, behaviorErr := P.ParseBehavior(behavior)
	if behaviorErr != nil {
		return nil, nil, fmt.Errorf("hako: provider behavior: %w", behaviorErr)
	}
	parsedFormat, formatErr := P.ParseRuleFormat(format)
	if formatErr != nil {
		return nil, nil, fmt.Errorf("hako: provider format: %w", formatErr)
	}
	if parsedBehavior == P.Classical && parsedFormat != P.MrsRule {
		// One cheap pass, whatever the profile. The capability decides which
		// owner-metadata kinds this platform can resolve -- a macOS packet
		// tunnel keeps PROCESS-NAME/-PATH and still loses UID and SOURCE-APP-*,
		// because it resolves paths but not those -- and nothing else here needs
		// the payload parsed. Judging whether each entry would build was the
		// same judgement upstream makes again at load, and it cost more than
		// everything else staging does put together.
		return stageClassicalProviderPayloadForApple(payload, parsedFormat, policy.processMetadata())
	}
	if err := ValidateProviderForIOS("rule", behavior, format, payload); err != nil {
		return nil, nil, err
	}
	return payload, nil, nil
}

// logKeptSourceRuleProvider is informational on purpose: the set still runs,
// as source, exactly as upstream runs it — only the compile acceleration is
// absent, and the reason says why. Both the staging that did the work and a
// cached start replay the same line.
func logKeptSourceRuleProvider(name, reason string) {
	log.Infoln("[Apple] rule provider %q is kept as source and rides as text on this profile: %s", name, reason)
}

// warnUnreadableRuleProvider is the provider-level counterpart of the per-rule
// warnings below: those report entries skipped inside a provider that still
// loads, this reports a provider that will not load at all. The distinction
// matters to whoever reads the log, because the remedy differs -- a skipped rule
// is usually a desktop-only rule kind, an unloadable provider is usually a bad
// URL or a format/extension mismatch.
//
// The reason is carried in full. It is the only place the cause survives: the
// core does not fail, so the App sees a started tunnel, and without this line a
// rule set that silently matches nothing would look identical to one that works.
func warnUnreadableRuleProvider(name string, cause error) {
	log.Warnln("[iOS] rule-provider %q cannot be read by this core and will load no rules: %v; "+
		"the configuration still starts and every other rule provider is unaffected, "+
		"matching upstream warn-and-continue (hub/executor/executor.go:333-337). "+
		"Check the provider's url/path and that its format matches the file it points at", name, cause)
}

func warnProviderMetadataNoops(name string, stripped []providerMetadataNoop) {
	for _, rule := range stripped {
		switch rule.reason {
		case providerNoopRuleUnsupported:
			log.Warnln("[iOS] rule-provider %q payload[%d] is not parseable or supported by this core and is skipped, matching upstream warn-and-continue; the remaining rules still load", name, rule.index)
		default:
			log.Warnln("[Apple] %s rule at rule-provider %q payload[%d] cannot execute in this Network Extension profile and is stripped from the private runtime copy (matches nothing, provider evaluation falls through)", rule.kind, name, rule.index)
		}
	}
}

func warnProviderEgressNoops(name string, stripped []providerEgressNoop) {
	for _, field := range stripped {
		log.Warnln("[iOS] proxy-provider %q payload[%d].%s has no Network Extension equivalent and is stripped from the private runtime copy; the provider still loads", name, field.index, field.field)
	}
}

// close releases this service's references. The staged directory stays on
// disk on purpose: it is the cache the next start reuses, and the sweep at
// staging time -- not stop time -- is what bounds it.
func (runtime *providerRuntime) close() {
	if runtime == nil {
		return
	}
	runtime.directory = ""
	runtime.entries = nil
}

func (s *BoxService) sideUpdateProvider(kind, name string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.providerRuntime == nil {
		return fmt.Errorf("hako: provider runtime is unavailable")
	}
	entry, exists := s.providerRuntime.entries[providerRuntimeKey(kind, name)]
	if !exists {
		return fmt.Errorf("hako: provider is not side-updateable")
	}
	if !entry.sideUpdateSafe {
		return fmt.Errorf("hako: provider affects Apple platform routes or lacks side-update metadata")
	}
	if entry.compiled {
		// Machine-checkable: the prefix is an exported constant, so the client
		// classifies by HakoSideUpdateDeferredPrefix instead of matching prose.
		// A deferral counted as a failure would have BGTaskScheduler back off
		// the whole refresh budget.
		// The live provider was built on the MRS artifact; validating or serving
		// the fresh text under that strategy is wrong in both directions. The
		// bytes are already in the published source, so the update applies at
		// the next foreground activation, which recompiles.
		return fmt.Errorf("%sthis rule set runs compiled; the update applies at the next activation", SideUpdateDeferredPrefix)
	}
	runtimePayload := payload
	switch kind {
	case "rule":
		prepared, stripped, err := prepareRuleProviderRuntimePayload(entry.behavior, entry.format, payload, s.providerRuntime.policy)
		if err != nil {
			return err
		}
		runtimePayload = prepared
		warnProviderMetadataNoops(name, stripped)
	case "proxy":
		prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(entry.format, payload, false)
		if err != nil {
			return err
		}
		runtimePayload = prepared
		warnProviderEgressNoops(name, stripped)
	default:
		return fmt.Errorf("hako: invalid provider kind")
	}
	rollbackPath := entry.runtimePath + ".rollback"
	_ = os.Remove(rollbackPath)
	if err := os.Link(entry.runtimePath, rollbackPath); err != nil {
		return fmt.Errorf("hako: preserve provider runtime rollback: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			_ = os.Remove(rollbackPath)
		}
	}()
	if err := writeRuntimeProviderFile(entry.runtimePath, runtimePayload); err != nil {
		_ = os.Remove(rollbackPath)
		return fmt.Errorf("hako: replace provider runtime: %w", err)
	}
	invalidateStagedProviderRecord(kind, name)

	var updateError error
	switch kind {
	case "proxy":
		provider, ok := tunnel.Providers()[name]
		if !ok || provider.VehicleType() != P.File {
			updateError = fmt.Errorf("hako: live proxy provider is unavailable")
		} else {
			updateError = provider.Update()
		}
	case "rule":
		provider, ok := tunnel.RuleProviders()[name]
		if !ok || provider.VehicleType() != P.File {
			updateError = fmt.Errorf("hako: live rule provider is unavailable")
		} else {
			updateError = provider.Update()
		}
	default:
		updateError = fmt.Errorf("hako: invalid provider kind")
	}
	if updateError == nil {
		committed = true
		return nil
	}
	if restoreError := os.Rename(rollbackPath, entry.runtimePath); restoreError != nil {
		return fmt.Errorf("hako: provider update failed and runtime rollback failed: %v", restoreError)
	}
	return fmt.Errorf("hako: provider update rejected: %w", updateError)
}
