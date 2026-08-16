package hako

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The consuming lane selects which core log lines to show a user by the "[Apple" prefix. It
// used to select by the word "stripped", and this batch added three notice families that do
// not contain it -- kept owner-metadata rules, unguarded controllers, and the unauthenticated
// LAN listener. That last one says "any device on any network this one joins can use it as a
// proxy": the user configured an open proxy, the core warned, and the app dropped the warning
// because the wording had changed.
//
// The lesson is not "always write [Apple". It is that the selection key was the wording, and
// wording moves. So the prefix is the key now, and this gate keeps the key stable: it does not
// judge what a prefix means, it just refuses to let a NEW one arrive unnoticed. A reader-facing
// family that invents its own tag would otherwise reach nobody, silently, exactly as before.
func TestNoNewLogPrefixArrivesUnnoticed(t *testing.T) {
	// Prefix AND level, because the prefix alone is not enough to say "reader-facing" -- the
	// consuming lane learned that by widening its selector to the prefix and pulling
	// "[Apple] default path -> en0 (index=6 expensive=false)" into a user-visible screen. That
	// line carries the marker and is instrumentation. Their selector is now prefix AND
	// not-info, so a real notice written with Infoln would be dropped silently, and a gate
	// that only recorded prefixes would stay green through it.
	type usage struct {
		levels string
		note   string
	}
	known := map[string]usage{
		"Apple|Warnln":                  {"Warnln", "reader-facing; this is the pair the app selects on"},
		"Apple %s|Warnln":               {"Warnln", "reader-facing, formatted with the runtime profile name"},
		"Apple NetworkExtension|Warnln": {"Warnln", "reader-facing; profile-independent statements"},
		"Apple|Infoln": {"Infoln", "instrumentation that happens to carry the reader prefix: the " +
			"physical-path trace and the geo compile summaries. The app filters these out by " +
			"level. A failure inside one of them gets its own Warnln -- see geosite_cache.go " +
			"and geoip_cache.go -- because a category that will not compile is a statement " +
			"about the user's rules, not about this process"},
		"Memory|Warnln": {"Warnln", "developer-facing: pressure and threshold telemetry"},
		"Memory|Infoln": {"Infoln", "developer-facing: pressure sampling"},
		"mem|Infoln":    {"Infoln", "developer-facing: allocator sampling"},
		"iOS|Warnln": {"Warnln", "developer-facing: provider staging and lifecycle internals. NOT " +
			"selected by the app -- if a line here ever needs to reach a user, give it an " +
			"[Apple prefix rather than widening the app's selector"},
		"iOS|Errorln": {"Errorln", "developer-facing: staging and lifecycle failures"},
		"iOS|Infoln":  {"Infoln", "developer-facing: staging progress"},
	}

	prefix := regexp.MustCompile(`log\.(Warnln|Errorln|Infoln)\("\[([^\]]+)\]`)
	found := map[string][]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		for _, match := range prefix.FindAllStringSubmatch(string(content), -1) {
			key := match[2] + "|" + match[1]
			found[key] = append(found[key], name)
		}
	}
	if len(found) == 0 {
		t.Fatal("no prefixed log calls found at all, which cannot be right -- the scan is broken, " +
			"and a broken scan passes silently")
	}

	for tag, files := range found {
		if _, isKnown := known[tag]; !isKnown {
			sort.Strings(files)
			t.Errorf("new prefix/level pair %q in %v. The app selects on BOTH: an [Apple prefix "+
				"at Infoln is filtered out as instrumentation, and a private tag at any level "+
				"reaches nobody. Decide which this is, then record it here", tag, files)
		}
	}
	for tag := range known {
		if _, stillUsed := found[tag]; !stillUsed {
			t.Errorf("pair %q is recorded here but no longer used; drop it so the list stays "+
				"a description rather than a wish", tag)
		}
	}
}

// Every reader-facing notice family, named individually.
//
// This is the half the enumeration gate above cannot do. That one catches a NEW prefix/level
// pair; it cannot catch an existing notice being downgraded from Warnln to Infoln, because
// "Apple|Infoln" is a legitimate pair already -- the physical-path trace and the geo summaries
// use it. Mutation proved that directly: downgrading publishDeviations to Infoln left the
// enumeration gate green, and the consuming lane would have dropped every deviation silently.
//
// So the families are listed by name and by emitting file. A family that stops emitting at
// Warnln fails here with its own name.
func TestEveryReaderFacingNoticeFamilyStaysAtWarnLevel(t *testing.T) {
	for family, site := range map[string]struct{ file, needle string }{
		"published deviations": {"config_deviations.go", "range deviations"},
	} {
		content, err := os.ReadFile(site.file)
		if err != nil {
			t.Fatalf("read %s: %v", site.file, err)
		}
		lines := strings.Split(string(content), "\n")
		emitted := false
		for index, line := range lines {
			if !strings.Contains(line, site.needle) {
				continue
			}
			for offset := 1; offset <= 4 && index+offset < len(lines); offset++ {
				if strings.Contains(lines[index+offset], `log.Warnln("[Apple`) {
					emitted = true
				}
			}
		}
		if !emitted {
			t.Errorf("%s no longer emits through an [Apple prefixed Warnln in %s; the app "+
				"selects on prefix AND level, so this family reaches nobody", family, site.file)
		}
	}

	content, err := os.ReadFile("config_pipeline.go")
	if err != nil {
		t.Fatalf("read config_pipeline.go: %v", err)
	}
	body := string(content)
	for family, needle := range map[string]string{
		"kept owner-metadata rules":    "summarizeMetadataRuleOccurrences",
		"unguarded controller":         "unguardedControllerNotices",
		"unauthenticated LAN listener": "unauthenticatedLANListenerNotices",
	} {
		// The emitting loop, not a byte window around the name. A window wide enough to hold
		// the loop is also wide enough to hold the NEIGHBOURING family's marker: when this was
		// first written as index +/- 400 chars, removing the marker from this family still
		// passed, because the family declared just above it still had one. Found by mutation,
		// which is the only reason it is not still that way.
		lines := strings.Split(body, "\n")
		emitted := false
		for lineIndex, line := range lines {
			if !strings.Contains(line, needle) || !strings.Contains(line, "range ") {
				continue
			}
			for offset := 1; offset <= 3 && lineIndex+offset < len(lines); offset++ {
				if strings.Contains(lines[lineIndex+offset], `log.Warnln("[Apple`) {
					emitted = true
				}
				if strings.Contains(lines[lineIndex+offset], "}") && offset > 1 {
					break
				}
			}
		}
		if !emitted {
			t.Errorf("%s no longer emits through an [Apple prefixed warning; the app selects on "+
				"that prefix and will drop this family without saying so", family)
		}
	}
}
