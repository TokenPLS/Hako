package session

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/transport/anytls/pipe"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce sync.Once
	stateMu sync.RWMutex
	dieHook func()
	dieErr  error

	reportOnce sync.Once
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if terminalErr := s.terminalError(); terminalErr != nil {
			err = terminalErr
		}
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if terminalErr := s.terminalError(); terminalErr != nil {
		return 0, terminalErr
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	once, dieHook := s.finish(net.ErrClosed)
	if once {
		if dieHook != nil {
			dieHook()
		}
	}
}

func (s *Stream) closeWithError(err error) error {
	once, dieHook := s.finish(err)
	if once {
		closeErr := s.sess.streamClosed(s.id)
		if dieHook != nil {
			dieHook()
		}
		return closeErr
	} else {
		return s.terminalError()
	}
}

func (s *Stream) finish(err error) (bool, func()) {
	var once bool
	var dieHook func()
	s.dieOnce.Do(func() {
		s.stateMu.Lock()
		s.dieErr = err
		dieHook = s.dieHook
		s.dieHook = nil
		s.stateMu.Unlock()
		s.pipeR.Close()
		once = true
	})
	return once, dieHook
}

func (s *Stream) terminalError() error {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.dieErr
}

func (s *Stream) setDieHook(dieHook func()) {
	s.stateMu.Lock()
	s.dieHook = dieHook
	s.stateMu.Unlock()
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
