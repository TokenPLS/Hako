# fswatch-noop

This module is the Apple-binding-only replacement for
`github.com/metacubex/fswatch`. It preserves the upstream public API and input
validation, but `Start` and `Close` are intentionally inert.

Hako publishes immutable configuration revisions and activates them explicitly.
Observing provider, certificate, or ECH files inside a Network Extension would
create redundant file descriptors and implicit mutation paths. The replacement
is scoped to `bind/hako/go.mod`; other Hako build modules continue to use the
upstream watcher.
