package hako

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No competitor's name in a string a reader can see.
//
// scripts/asc_listing_audit.py bans eleven names from App Store metadata,
// because guideline 2.3.7 does. It reads listing copy, and it cannot reach the
// strings this binary builds at runtime -- so "Shadowrocket field is not mapped
// by this importer build" was shipped as the message a user got for pasting
// their own subscription link. Two of the user's links produced it within an
// hour on 2026-08-28.
//
// The names stay legal in comments: they are how the dialects are identified
// and removing them would cost the reader of the code the only word that says
// which exporter a workaround is for. What must not carry them is anything
// formatted into an error, because that is what reaches a screen.
//
// Found by the macOS lane, which noticed its own audit script banning a word
// this tree was printing.
func TestNoCompetitorNameReachesAReader(t *testing.T) {
	// The same eleven the listing audit uses. Kept in step by hand rather than
	// parsed out of the Python: a second copy that drifts is better than a
	// derivation that silently reads nothing.
	banned := []string{
		"sing-box", "surge", "shadowrock", "shadowrocket", "stash", "loon",
		"quantumult", "clashx", "potatso", "kitsunebi", "pharos",
	}
	// Only strings that get formatted for a human.
	// The tree's own message producers count, not just the standard library's.
	// unsupportedProxyImportField is the one that built the sentence the user
	// actually saw -- "Shadowrocket field is not mapped by this importer build"
	// -- and a scan listing only fmt.Errorf could not see it. Poisoning that
	// exact string caught nothing twice: first because the producer and the
	// string sit on different lines, then because the producer was not in this
	// list at all. Two different reasons, the same empty result.
	producer := regexp.MustCompile(
		`(fmt\.Errorf\(|fmt\.Sprintf\(|errors\.New\(|log\.\w+ln\(|unsupportedProxyImportField\()`)

	roots := []string{".", filepath.Join("..", "..", "component", "dialer")}
	scanned, hits := 0, 0
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("cannot read %s: %v", root, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			scanned++
			// A producer and its string are often on different lines: Go wraps
			// long calls, and the message that shipped to users sat two lines
			// below its unsupportedProxyImportField(. The first version of this
			// scan required them on one line, so poisoning the exact string the
			// user saw caught nothing -- a predicate that cannot reach its
			// target, inside a gate written this hour.
			//
			// So a producer opens a window: the call's line and the few that
			// follow it, which is how far a wrapped argument list reaches.
			lines := strings.Split(string(body), "\n")
			window := 0
			for index, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				// A window opens at a producer and closes at the call's end, not
				// after a fixed count. Six lines caught proxy_import.go:983 --
				// `format := "sing-box-json"`, an internal identifier six lines
				// below an unrelated Errorf. A gate that reports an identifier
				// as user-visible text gets weakened until it stops working, and
				// the macOS lane's parallel scan classified those 25 correctly
				// as identifiers, not sentences.
				if producer.MatchString(line) {
					window = strings.Count(line, "(") - strings.Count(line, ")")
					if window < 0 {
						window = 0
					}
					// The producer's own line always counts.
					if !checkLine(t, name, index, trimmed, banned) {
						hits++
					}
					continue
				}
				if window == 0 {
					continue
				}
				window += strings.Count(line, "(") - strings.Count(line, ")")
				if window < 0 {
					window = 0
				}
				if !checkLine(t, name, index, trimmed, banned) {
					hits++
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source files; the roots are wrong, not the code")
	}
	t.Logf("scanned %d files for %d banned names; %d hit(s)", scanned, len(banned), hits)
}

// checkLine reports whether the line is clean, and complains when it is not.
func checkLine(t *testing.T, file string, index int, trimmed string, banned []string) bool {
	t.Helper()
	clean := true
	// A dotted field path is an identifier the client looks up, not a sentence
	// it shows. "sing-box.outbound.tls.enabled" reaches a screen inside
	// `proxy field %q is recognized but unsupported`, so it is not invisible --
	// but renaming it changes a key the client's table is written against, and
	// that is a three-lane decision rather than a lint. Exempted here on
	// purpose, with the boundary stated, and raised with the client lanes
	// 2026-08-28 rather than settled unilaterally.
	//
	// A sentence carrying the same word is NOT exempt: the whole point is that
	// "Shadowrocket field is not mapped by this importer build" was prose shown
	// to a user for pasting their own link.
	isFieldPath := func(literal string) bool {
		inner := strings.Trim(literal, `"`)
		if !strings.Contains(inner, ".") || strings.Contains(inner, " ") {
			return false
		}
		return !strings.ContainsAny(inner, "%:;,!?")
	}
	for _, literal := range regexp.MustCompile(`"([^"\\]|\\.)*"`).FindAllString(trimmed, -1) {
		if isFieldPath(literal) {
			continue
		}
		lowered := strings.ToLower(literal)
		for _, word := range banned {
			if strings.Contains(lowered, word) {
				clean = false
				t.Errorf("%s:%d formats %q into a message a reader can see. The listing audit bans "+
					"that word because guideline 2.3.7 does, and it cannot reach runtime "+
					"strings:\n\t%s", file, index+1, word, trimmed)
			}
		}
	}
	return clean
}
