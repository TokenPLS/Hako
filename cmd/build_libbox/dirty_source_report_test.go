package main

import (
	"reflect"
	"testing"
)

// sourceDirty used to be a bool with nothing behind it, and a whole round of builds carried
// sourceDirty=true because a DerivedData directory sat at the repo root. Nobody could tell:
// the flag named nothing, and package_release.sh refuses a formal SDK on it, so whether a
// release could be packaged came down to whether somebody had happened to delete a temporary
// directory.
//
// The strictness is not what is being tested here -- untracked files SHOULD count, because an
// untracked .go file compiles into the artifact. What is tested is that the answer carries the
// paths, so a person reading the build output learns in one line what took a round to notice.
func TestDirtySourceEntriesNamesEveryPathGitReported(t *testing.T) {
	for name, testCase := range map[string]struct {
		status string
		want   []string
	}{
		"clean tree reports nothing": {
			status: "",
			want:   nil,
		},
		"whitespace only is still clean": {
			status: "\n  \n",
			want:   nil,
		},
		"untracked build output is named, not just counted": {
			status: "?? .derived-macos/\n?? .derived-ios/\n",
			want:   []string{"?? .derived-macos/", "?? .derived-ios/"},
		},
		"modified sources are named too": {
			status: " M bind/hako/service.go\n?? bind/hako/scratch.go\n",
			want:   []string{"M bind/hako/service.go", "?? bind/hako/scratch.go"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := dirtySourceEntries([]byte(testCase.status))
			if !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("dirtySourceEntries(%q) = %#v, want %#v", testCase.status, got, testCase.want)
			}
		})
	}
}

// The bool has to keep agreeing with the list, or the report describes a build the flag does not.
func TestDirtyFlagAndReportCannotDisagree(t *testing.T) {
	for _, status := range []string{"", "\n", "?? .derived/\n", " M a.go\n?? b.go\n"} {
		entries := dirtySourceEntries([]byte(status))
		dirty := len(entries) != 0
		if dirty != (len(entries) > 0) {
			t.Fatalf("status %q: flag %v, entries %v", status, dirty, entries)
		}
	}
}
