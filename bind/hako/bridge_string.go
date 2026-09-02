package hako

import (
	"strings"
	"unicode/utf8"
)

// bridgeSafeString is the string twin of bridgeSafeError: the last stop
// before a Go string crosses the gomobile bridge, in either direction. The
// generated Objective-C glue decodes every crossing string as UTF-8 and a
// non-empty string holding bytes that are not valid UTF-8 decodes to nil.
// On a return value that nil lands in a nonnull-annotated slot; on a
// callback parameter it lands in a non-optional Swift argument; both are
// process-ending on the consumer side. Ordinary input can carry such bytes:
// a YAML document may hold arbitrary bytes in a string field, and log lines
// as well as upstream error sentences embed those bytes verbatim.
//
// A valid string passes through untouched, byte for byte. An invalid one
// keeps every readable byte and replaces only the undecodable ones with the
// Unicode replacement rune — encoding repair at the process boundary, never
// redaction.
func bridgeSafeString(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	return strings.ToValidUTF8(value, "�")
}

// The types below decorate the callback interfaces Swift implements. Every
// dispatch — a direct call, a stored method value, a goroutine — goes
// through the stored handler, so wrapping the object once where it enters
// covers every present and future call site. Embedding delegates the
// methods that carry no string.

type bridgeSafePlatformDecorator struct{ PlatformInterface }

func (p bridgeSafePlatformDecorator) WriteLog(message string) {
	p.PlatformInterface.WriteLog(bridgeSafeString(message))
}

func bridgeSafePlatform(platform PlatformInterface) PlatformInterface {
	if platform == nil {
		return nil
	}
	if _, ok := platform.(bridgeSafePlatformDecorator); ok {
		return platform
	}
	return bridgeSafePlatformDecorator{platform}
}

type bridgeSafeClashHandlerDecorator struct{ ClashAPIClientHandler }

func (h bridgeSafeClashHandlerDecorator) Disconnected(message string) {
	h.ClashAPIClientHandler.Disconnected(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteTraffic(message string) {
	h.ClashAPIClientHandler.WriteTraffic(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteMemory(message string) {
	h.ClashAPIClientHandler.WriteMemory(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteLogs(message string) {
	h.ClashAPIClientHandler.WriteLogs(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteConnections(message string) {
	h.ClashAPIClientHandler.WriteConnections(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteMode(message string) {
	h.ClashAPIClientHandler.WriteMode(bridgeSafeString(message))
}

func bridgeSafeClashHandler(handler ClashAPIClientHandler) ClashAPIClientHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeClashHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeClashHandlerDecorator{handler}
}

type bridgeSafeSTUNHandlerDecorator struct{ STUNTestHandler }

func (h bridgeSafeSTUNHandlerDecorator) OnError(message string) {
	h.STUNTestHandler.OnError(bridgeSafeString(message))
}

func bridgeSafeSTUNHandler(handler STUNTestHandler) STUNTestHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeSTUNHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeSTUNHandlerDecorator{handler}
}

type bridgeSafeNQHandlerDecorator struct{ NetworkQualityTestHandler }

func (h bridgeSafeNQHandlerDecorator) OnError(message string) {
	h.NetworkQualityTestHandler.OnError(bridgeSafeString(message))
}

func bridgeSafeNQHandler(handler NetworkQualityTestHandler) NetworkQualityTestHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeNQHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeNQHandlerDecorator{handler}
}
