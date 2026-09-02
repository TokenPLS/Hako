package hako

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/TokenPLS/Hako/log"
)

func TestBridgeSafeString(t *testing.T) {
	t.Run("valid stays byte-identical", func(t *testing.T) {
		message := "hako: 节点 🚀 café \ttrailing "
		if got := bridgeSafeString(message); got != message {
			t.Fatalf("valid string must pass byte-identical, got %q", got)
		}
	})
	t.Run("empty stays empty", func(t *testing.T) {
		if got := bridgeSafeString(""); got != "" {
			t.Fatalf("empty must stay empty, got %q", got)
		}
	})
	t.Run("invalid bytes repaired, rest verbatim", func(t *testing.T) {
		got := bridgeSafeString("initial proxy provider \xfe\xdf error")
		if !utf8.ValidString(got) {
			t.Fatalf("still invalid: %q", got)
		}
		if !strings.HasPrefix(got, "initial proxy provider ") || !strings.HasSuffix(got, " error") {
			t.Fatalf("sentence must survive verbatim, got %q", got)
		}
	})
}

type bridgeRecordingPlatform struct {
	PlatformInterface
	lines chan string
}

func (p *bridgeRecordingPlatform) WriteLog(message string) { p.lines <- message }

func TestPlatformWriteLogCrossesValidUTF8(t *testing.T) {
	fake := &bridgeRecordingPlatform{lines: make(chan string, 64)}
	writer := redirectLogs(fake)
	defer stopLogRedirect(writer)

	log.Errorln("initial proxy provider %s error: parse failed", "\xfe\xdf")
	log.Errorln("initial proxy provider %s error: parse failed", "节点-普通")

	var got []string
	for len(got) < 2 {
		select {
		case line := <-fake.lines:
			if strings.Contains(line, "initial proxy provider") {
				got = append(got, line)
			}
		case <-t.Context().Done():
			t.Fatalf("timed out; captured %d line(s): %q", len(got), got)
		}
	}
	if !utf8.ValidString(got[0]) {
		t.Fatalf("invalid UTF-8 crossed the platform log bridge: %q", got[0])
	}
	if !strings.Contains(got[1], "节点-普通") {
		t.Fatalf("valid log line must arrive verbatim, got %q", got[1])
	}
	if strings.Contains(got[1], "�") {
		t.Fatalf("valid log line must not gain replacement runes: %q", got[1])
	}
}

type bridgeRecordingClashHandler struct {
	ClashAPIClientHandler
	messages []string
}

func (h *bridgeRecordingClashHandler) WriteLogs(message string) {
	h.messages = append(h.messages, message)
}
func (h *bridgeRecordingClashHandler) Disconnected(message string) {
	h.messages = append(h.messages, message)
}

type bridgeRecordingSTUNHandler struct {
	STUNTestHandler
	errors []string
}

func (h *bridgeRecordingSTUNHandler) OnError(message string) { h.errors = append(h.errors, message) }

func TestBridgeCallbackDecorators(t *testing.T) {
	t.Run("clash api handler", func(t *testing.T) {
		inner := &bridgeRecordingClashHandler{}
		wrapped := bridgeSafeClashHandler(inner)
		wrapped.WriteLogs("log \xfe line")
		wrapped.Disconnected("bye 好")
		if len(inner.messages) != 2 {
			t.Fatalf("want 2 messages, got %d", len(inner.messages))
		}
		if !utf8.ValidString(inner.messages[0]) {
			t.Fatalf("WriteLogs crossed invalid: %q", inner.messages[0])
		}
		if inner.messages[1] != "bye 好" {
			t.Fatalf("valid message must pass byte-identical, got %q", inner.messages[1])
		}
	})
	t.Run("stun handler", func(t *testing.T) {
		inner := &bridgeRecordingSTUNHandler{}
		wrapped := bridgeSafeSTUNHandler(inner)
		wrapped.OnError("stun \xff fail")
		if len(inner.errors) != 1 || !utf8.ValidString(inner.errors[0]) {
			t.Fatalf("OnError crossed invalid: %q", inner.errors)
		}
	})
	t.Run("wrapping is idempotent", func(t *testing.T) {
		inner := &bridgeRecordingClashHandler{}
		once := bridgeSafeClashHandler(inner)
		twice := bridgeSafeClashHandler(once)
		if once != twice {
			t.Fatal("wrapping an already-wrapped handler must return it unchanged")
		}
	})
}
