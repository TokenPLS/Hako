package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"unsafe"

	"github.com/TokenPLS/Hako/common/buf"
	N "github.com/TokenPLS/Hako/common/net"
	"github.com/TokenPLS/Hako/log"

	"github.com/gofrs/uuid/v5"
)

var (
	_ N.ExtendedConn = (*Conn)(nil)
)

type Conn struct {
	net.Conn // should be *vless.Conn
	N.ExtendedReader
	N.ExtendedWriter
	userUUID uuid.UUID

	// net.Conn permits concurrent method calls. Vision has direction-local
	// parsers plus a small amount of state shared by Read, Write, Close and the
	// headroom/unwrap helpers, so serialize each direction and guard the shared
	// transitions separately. Never hold stateMu across network I/O.
	readMu  sync.Mutex
	writeMu sync.Mutex
	stateMu sync.RWMutex

	// [*tls.Conn] or other tls-like [net.Conn]'s internal variables
	netConn  net.Conn      // tlsConn.NetConn()
	input    *bytes.Reader // &tlsConn.input or nil
	rawInput *bytes.Buffer // &tlsConn.rawInput or nil

	packetsToFilter            int
	isTLS                      bool
	isTLS12orAbove             bool
	enableXTLS                 bool
	cipher                     uint16
	remainingServerHello       uint16
	readRemainingBuffer        *buf.Buffer
	readRemainingContent       int
	readRemainingPadding       int
	readProcess                bool
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writeDirect                bool
	writeOnceUserUUID          []byte
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()

	if vc.readProcessing() {
		buffer := buf.With(b)
		err := vc.readBuffer(buffer)
		if unsafe.SliceData(buffer.Bytes()) != unsafe.SliceData(b) { // buffer.Bytes() not at the beginning of b
			copy(b, buffer.Bytes())
		}
		return buffer.Len(), err
	}
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()
	return vc.readBuffer(buffer)
}

func (vc *Conn) readBuffer(buffer *buf.Buffer) error {
	if vc.readRemainingBuffer != nil {
		_, err := buffer.ReadOnceFrom(vc.readRemainingBuffer)
		if vc.readRemainingBuffer.IsEmpty() {
			vc.readRemainingBuffer.Release()
			vc.readRemainingBuffer = nil
		}
		return err
	}
	if vc.readRemainingContent > 0 {
		readSize := xrayBufSize          // at least read xrayBufSize
		if buffer.FreeLen() > readSize { // input buffer larger than xrayBufSize, read as much as possible
			readSize = buffer.FreeLen()
		}
		if readSize > vc.readRemainingContent { // don't read out of bounds
			readSize = vc.readRemainingContent
		}

		readBuffer := buffer
		if buffer.FreeLen() < readSize {
			readBuffer = buf.NewSize(readSize)
			vc.readRemainingBuffer = readBuffer
		}
		n, err := vc.ExtendedReader.Read(readBuffer.FreeBytes()[:readSize])
		readBuffer.Truncate(n)
		vc.readRemainingContent -= n
		vc.FilterTLS(readBuffer.Bytes())
		if vc.readRemainingBuffer != nil {
			innerErr := vc.readBuffer(buffer) // back to top but not losing err
			if err != nil {
				err = innerErr
			}
		}
		return err
	}
	if vc.readRemainingPadding > 0 {
		n, err := io.CopyN(io.Discard, vc.ExtendedReader, int64(vc.readRemainingPadding))
		if err != nil {
			return err
		}
		vc.readRemainingPadding -= int(n)
	}
	if readProcess, readLastCommand := vc.readCommandState(); readProcess {
		switch readLastCommand {
		case commandPaddingContinue:
			//if vc.isTLS || vc.packetsToFilter > 0 {
			need := PaddingHeaderLen
			if !vc.shouldFilterReadUUID() {
				need = PaddingHeaderLen - uuid.Size
			}
			var header []byte
			if buffer.FreeLen() < need {
				header = make([]byte, need)
			} else {
				header = buffer.FreeBytes()[:need]
			}
			_, err := io.ReadFull(vc.ExtendedReader, header)
			if err != nil {
				return err
			}
			if vc.consumeReadUUIDFilter() {
				if !bytes.Equal(vc.userUUID.Bytes(), header[:uuid.Size]) {
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s", uuid.FromBytesOrNil(header[:uuid.Size]))
					log.Errorln(err.Error())
					return err
				}
				header = header[uuid.Size:]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.setReadLastCommand(header[0])
			log.Debugln("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
				header[0], vc.readRemainingContent, vc.readRemainingPadding)
			return vc.readBuffer(buffer)
			//}
		case commandPaddingEnd:
			vc.setReadProcessing(false)
			return vc.readBuffer(buffer)
		case commandPaddingDirect:
			needReturn := false
			if vc.input != nil {
				_, err := buffer.ReadOnceFrom(vc.input)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				if vc.input.Len() == 0 {
					needReturn = true
					*vc.input = bytes.Reader{} // full reset
					vc.input = nil
				} else { // buffer is full
					return nil
				}
			}
			if vc.rawInput != nil {
				_, err := buffer.ReadOnceFrom(vc.rawInput)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				needReturn = true
				if vc.rawInput.Len() == 0 {
					*vc.rawInput = bytes.Buffer{} // full reset
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.setReadProcessing(false)
				vc.ExtendedReader = N.NewExtendedReader(vc.netConn)
				log.Debugln("XTLS Vision direct read start")
			}
			if needReturn {
				return nil
			}
		default:
			err := fmt.Errorf("XTLS Vision read unknown command: %d", readLastCommand)
			log.Debugln(err.Error())
			return err
		}
	}
	return vc.ExtendedReader.ReadBuffer(buffer)
}

type serializedWriter struct {
	*Conn
}

func (w serializedWriter) WriteBuffer(buffer *buf.Buffer) error {
	return w.Conn.writeBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()

	if vc.writeFiltering() {
		// N.WriteBuffer needs the Vision headroom/unwrap methods. The wrapper
		// preserves those methods while bypassing the public locking entry point.
		return N.WriteBuffer(serializedWriter{Conn: vc}, buf.As(p))
	}
	return vc.ExtendedWriter.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) (err error) {
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()
	return vc.writeBuffer(buffer)
}

func (vc *Conn) writeBuffer(buffer *buf.Buffer) (err error) {
	if vc.writeFiltering() {
		if buffer.IsEmpty() {
			vc.applyPadding(buffer, commandPaddingContinue, true) // we do a long padding to hide vless header
			return vc.ExtendedWriter.WriteBuffer(buffer)
		}

		vc.FilterTLS(buffer.Bytes())
		filterState := vc.filterState()
		buffers := vc.ReshapeBuffer(buffer)
		applyPadding := true
		for i, buffer := range buffers {
			command := commandPaddingContinue
			if applyPadding {
				if filterState.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
					command = commandPaddingEnd
					if filterState.enableXTLS {
						command = commandPaddingDirect
					}
					vc.finishWriteFiltering(command == commandPaddingDirect)
					applyPadding = false
				} else if !filterState.isTLS12orAbove && filterState.packetsToFilter <= 1 {
					command = commandPaddingEnd
					vc.finishWriteFiltering(false)
					applyPadding = false
				}
				vc.applyPadding(buffer, command, filterState.isTLS)
			}

			err = vc.ExtendedWriter.WriteBuffer(buffer)
			if err != nil {
				buf.ReleaseMulti(buffers[i:]) // release unwritten buffers
				return
			}
			if command == commandPaddingDirect {
				vc.ExtendedWriter = N.NewExtendedWriter(vc.netConn)
				log.Debugln("XTLS Vision direct write start")
				//time.Sleep(5 * time.Millisecond)
			}
		}
		return err
	}
	/*if vc.writeDirect {
		log.Debugln("XTLS Vision Direct write, payloadLen=%d", buffer.Len())
	}*/
	return vc.ExtendedWriter.WriteBuffer(buffer)
}

func (vc *Conn) FrontHeadroom() int {
	readFilterUUID, writeOnceUserUUID, writeFilterApplicationData := vc.headroomState()
	fontHeadroom := PaddingHeaderLen - uuid.Size
	if readFilterUUID || writeOnceUserUUID {
		fontHeadroom = PaddingHeaderLen
	}
	if writeFilterApplicationData { // The writer may be replaced, add the required value for vc.netConn
		if abs := N.CalculateFrontHeadroom(vc.netConn) - N.CalculateFrontHeadroom(vc.Conn); abs > 0 {
			fontHeadroom += abs
		}
	}
	return fontHeadroom
}

func (vc *Conn) RearHeadroom() int {
	rearHeadroom := 500 + 900
	if vc.writeFiltering() { // The writer may be replaced, add the required value for vc.netConn
		if abs := N.CalculateRearHeadroom(vc.netConn) - N.CalculateRearHeadroom(vc.Conn); abs > 0 {
			rearHeadroom += abs
		}
	}
	return rearHeadroom
}

func (vc *Conn) NeedHandshake() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.writeOnceUserUUID != nil
}

func (vc *Conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (vc *Conn) Upstream() any {
	vc.stateMu.RLock()
	direct := vc.writeDirect || vc.readLastCommand == commandPaddingDirect
	vc.stateMu.RUnlock()
	if direct {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) ReaderPossiblyReplaceable() bool {
	return vc.readProcessing()
}

func (vc *Conn) ReaderReplaceable() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return !vc.readProcess && vc.readLastCommand == commandPaddingDirect
}

func (vc *Conn) WriterPossiblyReplaceable() bool {
	return vc.writeFiltering()
}

func (vc *Conn) WriterReplaceable() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.writeDirect
}

type tlsFilterState struct {
	packetsToFilter int
	isTLS           bool
	isTLS12orAbove  bool
	enableXTLS      bool
}

func (vc *Conn) filterState() tlsFilterState {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return tlsFilterState{
		packetsToFilter: vc.packetsToFilter,
		isTLS:           vc.isTLS,
		isTLS12orAbove:  vc.isTLS12orAbove,
		enableXTLS:      vc.enableXTLS,
	}
}

func (vc *Conn) readProcessing() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.readProcess
}

func (vc *Conn) readCommandState() (bool, byte) {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.readProcess, vc.readLastCommand
}

func (vc *Conn) shouldFilterReadUUID() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.readFilterUUID
}

func (vc *Conn) consumeReadUUIDFilter() bool {
	vc.stateMu.Lock()
	defer vc.stateMu.Unlock()
	if !vc.readFilterUUID {
		return false
	}
	vc.readFilterUUID = false
	return true
}

func (vc *Conn) setReadLastCommand(command byte) {
	vc.stateMu.Lock()
	vc.readLastCommand = command
	vc.stateMu.Unlock()
}

func (vc *Conn) setReadProcessing(process bool) {
	vc.stateMu.Lock()
	vc.readProcess = process
	vc.stateMu.Unlock()
}

func (vc *Conn) writeFiltering() bool {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.writeFilterApplicationData
}

func (vc *Conn) finishWriteFiltering(direct bool) {
	vc.stateMu.Lock()
	vc.writeDirect = direct
	vc.writeFilterApplicationData = false
	vc.stateMu.Unlock()
}

func (vc *Conn) applyPadding(buffer *buf.Buffer, command byte, isTLS bool) {
	vc.stateMu.Lock()
	ApplyPadding(buffer, command, &vc.writeOnceUserUUID, isTLS)
	vc.stateMu.Unlock()
}

func (vc *Conn) headroomState() (readFilterUUID bool, writeOnceUserUUID bool, writeFilterApplicationData bool) {
	vc.stateMu.RLock()
	defer vc.stateMu.RUnlock()
	return vc.readFilterUUID, vc.writeOnceUserUUID != nil, vc.writeFilterApplicationData
}

func (vc *Conn) Close() error {
	if vc.ReaderReplaceable() || vc.WriterReplaceable() { // ignore send closeNotify alert in tls.Conn
		return vc.netConn.Close()
	}
	return vc.Conn.Close()
}
