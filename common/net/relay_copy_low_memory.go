//go:build with_low_memory

package net

import (
	"errors"
	"io"
	"syscall"

	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

// lowMemoryRelayMTU bounds each direction of an idle TCP relay to one 2 KiB
// copy buffer. A 4 KiB baseline still reached Apple's critical memory-pressure
// signal during the signed 500-connection gate even though phys_footprint
// remained below the engineering budget. TCP streaming permits a 4064-byte
// TUN payload to be read in multiple chunks, while protocol writers that need
// framing headroom still receive it through ReadWaitOptions and sources or
// destinations that declare a larger MTU retain their declared requirement.
const lowMemoryRelayMTU = 2 * 1024

// relayCopy keeps sing's cached-reader, replaceable handshake and counter
// semantics. Only the final streaming buffer is constrained. This is kept
// local rather than changing sing's global low-memory buffer because UDP and
// protocol transports have different allocation and framing requirements.
func relayCopy(destination io.Writer, source io.Reader) (n int64, err error) {
	if source == nil {
		return 0, E.New("nil reader")
	}
	if destination == nil {
		return 0, E.New("nil writer")
	}

	originSource := source
	var readCounters, writeCounters []N.CountFunc
	possiblyReplaceable := bufio.MaxCopyExtendedOnceTimes
	for {
		source, readCounters = N.UnwrapCountReader(source, readCounters)
		destination, writeCounters = N.UnwrapCountWriter(destination, writeCounters)

		if cachedSource, isCached := source.(N.CachedReader); isCached {
			cachedBuffer := cachedSource.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err = destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					return
				}
				countRelayBytes(readCounters, int64(dataLen))
				countRelayBytes(writeCounters, int64(dataLen))
				continue
			}
		}

		replaceableReader, readerPossiblyReplaceable := source.(N.ReaderPossiblyReplaceable)
		replaceableWriter, writerPossiblyReplaceable := destination.(N.WriterPossiblyReplaceable)
		if possiblyReplaceable != 0 && ((readerPossiblyReplaceable && replaceableReader.ReaderPossiblyReplaceable()) ||
			(writerPossiblyReplaceable && replaceableWriter.WriterPossiblyReplaceable())) {
			possiblyReplaceable--
			var copied int64
			copied, err = bufio.CopyExtendedOnce(newBoundedRelayWriter(destination), source, readCounters, writeCounters)
			n += copied
			if err != nil {
				if n == copied {
					err = N.ReportHandshakeFailure(originSource, err)
				}
				if errors.Is(err, io.EOF) {
					err = nil
				}
				return
			}
			continue
		}
		break
	}

	destinationWriter := newBoundedRelayWriter(destination)
	var copied int64
	copied, err = bufio.CopyWithCounters(
		destinationWriter,
		source,
		originSource,
		readCounters,
		writeCounters,
	)
	n += copied
	return
}

func newBoundedRelayWriter(destination io.Writer) *boundedRelayWriter {
	return &boundedRelayWriter{
		ExtendedWriter: bufio.NewExtendedWriter(destination),
		upstream:       destination,
	}
}

func countRelayBytes(counters []N.CountFunc, size int64) {
	for _, counter := range counters {
		counter(size)
	}
}

type boundedRelayWriter struct {
	N.ExtendedWriter
	upstream io.Writer
}

func (*boundedRelayWriter) WriterMTU() int {
	return lowMemoryRelayMTU
}

func (w *boundedRelayWriter) UpstreamWriter() any {
	return w.ExtendedWriter
}

// Preserve sing's zero-copy syscall path on platforms where it is available.
// Apple builds fall back to the bounded ExtendedWriter path because sing's
// non-Linux splice implementation intentionally reports handled=false.
func (w *boundedRelayWriter) SyscallConn() (syscall.RawConn, error) {
	if syscallConn, ok := w.upstream.(syscall.Conn); ok {
		return syscallConn.SyscallConn()
	}
	return nil, syscall.EINVAL
}
