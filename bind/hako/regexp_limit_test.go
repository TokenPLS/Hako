package hako

import (
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

func TestRuntimeRegularExpressionsHaveIOSMatchDeadline(t *testing.T) {
	expression, err := regexp2.Compile(`(.+)*\?`, regexp2.None)
	if err != nil {
		t.Fatal(err)
	}
	if expression.MatchTimeout != maximumRegularExpressionMatchDurationForIOS {
		t.Fatalf("match timeout = %s, want %s", expression.MatchTimeout, maximumRegularExpressionMatchDurationForIOS)
	}

	started := time.Now()
	matched, err := expression.MatchString(strings.Repeat("a", 4096))
	if err == nil {
		t.Fatalf("catastrophic expression unexpectedly completed: matched=%t elapsed=%s", matched, time.Since(started))
	}
	if time.Since(started) > time.Second {
		t.Fatalf("catastrophic expression exceeded the bounded iOS deadline: %s", time.Since(started))
	}
}
