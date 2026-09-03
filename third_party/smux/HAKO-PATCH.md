# Hako smux patch

This directory is a source snapshot of `github.com/metacubex/smux` at
`d0c8756d3141ce2c9aa1046df6a93985441c6033`, the revision pinned by mihomo.
The upstream MIT license is preserved alongside the source.

Hako makes one behavioral ownership change in `session.go`:
`writeFrameInternal` clones a frame payload before handing it to the
asynchronous shaper. The pinned implementation can return on session close,
socket error, or deadline while `sendLoop` still reads the caller's slice.
Callers may reuse that slice as soon as `Write` returns, so retaining it causes
a real data race during full-duplex XHTTP/sing-mux teardown.

Remove the local `go.mod` replacement after an upstream meta revision contains
an equivalent ownership fix and the targeted XHTTP race test passes against
that revision.
