# Hako ReTLS patch

This directory is a source snapshot of
`github.com/metacubex/restls-client-go` v0.1.8. The upstream MIT and ReTLS
license files are preserved alongside the code.

Hako changes only four debug statements in `conn.go`. The upstream statements
evaluate the opposite traffic direction's mutable counter while a full-duplex
`net.Conn` is reading and writing concurrently. Those values are diagnostic
only and are not part of authentication, framing, counters, or protocol
behavior. Hako omits the opposite-direction counter from each statement so the
connection retains full duplex operation without a data race.

Remove the local `go.mod` replacement after an upstream release contains an
equivalent fix and the targeted ReTLS race tests pass against that release.
