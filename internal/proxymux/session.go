package proxymux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var errStreamDeadlineChanged = errors.New("proxymux: stream deadline changed")

const (
	defaultMaxStreams        = 128
	defaultOpenTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultKeepAliveInterval = 20 * time.Second
	streamReadQueueFrames    = 8
	maxSessionStreams        = 512
)

// OpenHandler validates an incoming logical stream request and returns the
// already-connected TCP target. It must enforce role-specific target allowlists.
// The returned connection is relayed to the stream by Session.
type OpenHandler func(ctx context.Context, frameType Type, payload []byte) (net.Conn, error)

// SessionOptions bounds resources for one authenticated transport connection.
type SessionOptions struct {
	// Initiator assigns odd stream IDs to this endpoint; the accepting endpoint
	// assigns even IDs. Exactly one side must be the initiator.
	Initiator bool
	MaxStreams int
	OpenTimeout time.Duration
	WriteTimeout time.Duration
	KeepAliveInterval time.Duration
	OnOpen OpenHandler
}

// Session multiplexes independent logical TCP streams over one already
// authenticated and encrypted net.Conn. It makes no routing, TUN, firewall,
// NAT, or sysctl changes.
type Session struct {
	conn net.Conn
	ctx context.Context
	cancel context.CancelFunc
	done chan struct{}
	closeOnce sync.Once

	initiator bool
	nextID uint32
	maxStreams int
	openTimeout time.Duration
	writeTimeout time.Duration
	keepAliveInterval time.Duration
	onOpen OpenHandler

	outbound chan Frame
	mu sync.Mutex
	streams map[uint32]*Stream
	closedIDs map[uint32]struct{}
	closedOrder []uint32

	errMu sync.RWMutex
	err error
	lastPong atomic.Int64
	pingSeq atomic.Uint64
}

// NewSession starts the read, write, and keepalive loops on an established
// authenticated connection. It does not create a network listener itself.
func NewSession(parent context.Context, conn net.Conn, opts SessionOptions) (*Session, error) {
	if conn == nil {
		return nil, errors.New("proxymux: connection is required")
	}
	if parent == nil {
		parent = context.Background()
	}
	if opts.MaxStreams <= 0 {
		opts.MaxStreams = defaultMaxStreams
	}
	if opts.MaxStreams > maxSessionStreams {
		cancel()
		_ = conn.Close()
		return nil, fmt.Errorf("proxymux: MaxStreams exceeds hard limit of %d", maxSessionStreams)
	}
	if opts.OpenTimeout <= 0 {
		opts.OpenTimeout = defaultOpenTimeout
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = defaultWriteTimeout
	}
	if opts.KeepAliveInterval <= 0 {
		opts.KeepAliveInterval = defaultKeepAliveInterval
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Session{
		conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		initiator: opts.Initiator, maxStreams: opts.MaxStreams,
		openTimeout: opts.OpenTimeout, writeTimeout: opts.WriteTimeout,
		keepAliveInterval: opts.KeepAliveInterval, onOpen: opts.OnOpen,
		outbound: make(chan Frame, 256), streams: make(map[uint32]*Stream), closedIDs: make(map[uint32]struct{}),
	}
	if opts.Initiator {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastPong.Store(time.Now().UnixNano())
	go s.writeLoop()
	go s.readLoop()
	go s.keepAliveLoop()
	go func() {
		select {
		case <-ctx.Done():
			s.shutdown(ctx.Err())
		case <-s.done:
		}
	}()
	return s, nil
}

// Done closes when the shared transport has failed or has been closed.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports the transport termination reason, or nil while it is active.
func (s *Session) Err() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	return s.err
}

// Close ends the entire multiplexed session and all of its streams.
func (s *Session) Close() error {
	s.shutdown(net.ErrClosed)
	return nil
}

// Open requests one new logical stream. The remote side must accept the
// requested operation and return OPEN_OK before the stream is usable.
func (s *Session) Open(frameType Type, payload []byte) (*Stream, error) {
	if frameType != TypeOpenDirect && frameType != TypeOpenReverse {
		return nil, errors.New("proxymux: Open requires OPEN_DIRECT or OPEN_REVERSE")
	}
	if err := validateHeader(frameType, 1, uint32(len(payload))); err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, errors.New("proxymux: open request payload is required")
	}
	if s.isDone() {
		return nil, s.sessionError()
	}

	s.mu.Lock()
	if s.isDone() {
		s.mu.Unlock()
		return nil, s.sessionError()
	}
	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		return nil, errors.New("proxymux: maximum stream count reached")
	}
	id, err := s.allocateIDLocked()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	st := newStream(s, id, true)
	s.streams[id] = st
	s.mu.Unlock()

	deadline := time.Now().Add(s.openTimeout)
	if err := s.sendFrame(Frame{Type: frameType, StreamID: id, Payload: payload}, deadline, nil); err != nil {
		st.abort(err)
		return nil, err
	}

	timer := time.NewTimer(s.openTimeout)
	defer timer.Stop()
	select {
	case openErr := <-st.openResult:
		if openErr != nil {
			return nil, openErr
		}
		if st.isReset() || s.isDone() {
			st.abort(s.sessionError())
			return nil, s.sessionError()
		}
		return st, nil
	case <-timer.C:
		err := os.ErrDeadlineExceeded
		st.abort(err)
		return nil, fmt.Errorf("proxymux: open request timed out: %w", err)
	case <-s.done:
		return nil, s.sessionError()
	}
}

func (s *Session) allocateIDLocked() (uint32, error) {
	for attempts := 0; attempts < 1<<16; attempts++ {
		id := s.nextID
		s.nextID += 2
		if s.nextID < 2 {
			if s.initiator {
				s.nextID = 1
			} else {
				s.nextID = 2
			}
		}
		if id == 0 {
			continue
		}
		if _, exists := s.streams[id]; !exists {
			return id, nil
		}
	}
	return 0, errors.New("proxymux: could not allocate a stream ID")
}

func newStream(session *Session, id uint32, local bool) *Stream {
	return &Stream{
		session: session, id: id, localOpen: local,
		openPending: local, openResult: make(chan error, 1),
		readCh: make(chan []byte, streamReadQueueFrames),
		readDeadlineChanged: make(chan struct{}),
		writeDeadlineChanged: make(chan struct{}),
	}
}

func (s *Session) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Session) sessionError() error {
	if err := s.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

func (s *Session) sendFrame(frame Frame, deadline time.Time, changed <-chan struct{}) error {
	if err := validateHeader(frame.Type, frame.StreamID, uint32(len(frame.Payload))); err != nil {
		return err
	}
	frame.Payload = append([]byte(nil), frame.Payload...)
	for {
		if s.isDone() {
			return s.sessionError()
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(left)
			timeout = timer.C
		}
		select {
		case s.outbound <- frame:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			return s.sessionError()
		case <-timeout:
			return os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			return errStreamDeadlineChanged
		}
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case frame := <-s.outbound:
			if s.isDone() {
				return
			}
			if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
				s.shutdown(fmt.Errorf("proxymux: set transport write deadline: %w", err))
				return
			}
			if err := WriteFrame(s.conn, frame); err != nil {
				s.shutdown(fmt.Errorf("proxymux: write transport frame: %w", err))
				return
			}
			_ = s.conn.SetWriteDeadline(time.Time{})
		}
	}
}

func (s *Session) readLoop() {
	for {
		frame, err := ReadFrame(s.conn)
		if err != nil {
			s.shutdown(fmt.Errorf("proxymux: read transport frame: %w", err))
			return
		}
		if err := s.handleFrame(frame); err != nil {
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) keepAliveLoop() {
	ticker := time.NewTicker(s.keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastPong.Load())) > 3*s.keepAliveInterval {
				s.shutdown(errors.New("proxymux: keepalive timeout"))
				return
			}
			seq := s.pingSeq.Add(1)
			var payload [8]byte
			for i := 7; i >= 0; i-- {
				payload[i] = byte(seq)
				seq >>= 8
			}
			if err := s.sendFrame(Frame{Type: TypePing, Payload: payload[:]}, time.Now().Add(s.writeTimeout), nil); err != nil {
				s.shutdown(fmt.Errorf("proxymux: send keepalive: %w", err))
				return
			}
		}
	}
}

func (s *Session) handleFrame(frame Frame) error {
	switch frame.Type {
	case TypePing:
		return s.sendFrame(Frame{Type: TypePong, Payload: frame.Payload}, time.Now().Add(s.writeTimeout), nil)
	case TypePong:
		s.lastPong.Store(time.Now().UnixNano())
		return nil
	case TypeOpenDirect, TypeOpenReverse:
		return s.handleRemoteOpen(frame)
	case TypeOpenOK:
		st, ok := s.getStream(frame.StreamID)
		if !ok {
			if s.localOwnsID(frame.StreamID) && s.wasClosed(frame.StreamID) {
				return s.sendFrame(Frame{Type: TypeClose, StreamID: frame.StreamID, Payload: []byte{closeFlagReset}}, time.Now().Add(s.writeTimeout), nil)
			}
			return fmt.Errorf("proxymux: unexpected OPEN_OK for stream %d", frame.StreamID)
		}
		if !st.localOpen {
			return fmt.Errorf("proxymux: OPEN_OK targets a remotely opened stream %d", frame.StreamID)
		}
		st.mu.Lock()
		if st.reset {
			st.mu.Unlock()
			_ = s.sendFrame(Frame{Type: TypeClose, StreamID: st.id, Payload: []byte{closeFlagReset}}, time.Now().Add(s.writeTimeout), nil)
			s.removeStream(st)
			return nil
		}
		if !st.openPending {
			st.mu.Unlock()
			return fmt.Errorf("proxymux: duplicate OPEN_OK for stream %d", frame.StreamID)
		}
		st.openPending = false
		st.ready = true
		st.mu.Unlock()
		st.resolveOpen(nil)
		return nil
	case TypeOpenError:
		st, ok := s.getStream(frame.StreamID)
		if !ok {
			if s.localOwnsID(frame.StreamID) && s.wasClosed(frame.StreamID) {
				return nil
			}
			return fmt.Errorf("proxymux: unexpected OPEN_ERROR for stream %d", frame.StreamID)
		}
		if !st.localOpen {
			return fmt.Errorf("proxymux: OPEN_ERROR targets a remotely opened stream %d", frame.StreamID)
		}
		openErr := errors.New("proxymux: remote rejected stream open")
		st.mu.Lock()
		st.reset = true
		st.writeClosed = true
		st.mu.Unlock()
		st.resolveOpen(openErr)
		st.endRead(openErr)
		s.removeStream(st)
		return nil
	case TypeData:
		st, ok := s.getStream(frame.StreamID)
		if !ok {
			if s.wasClosed(frame.StreamID) {
				return nil
			}
			return fmt.Errorf("proxymux: DATA for unknown stream %d", frame.StreamID)
		}
		if err := st.pushData(frame.Payload); err != nil {
			st.abort(err)
		}
		return nil
	case TypeClose:
		st, ok := s.getStream(frame.StreamID)
		if !ok {
			if s.wasClosed(frame.StreamID) {
				return nil
			}
			return fmt.Errorf("proxymux: CLOSE for unknown stream %d", frame.StreamID)
		}
		if frame.Payload[0] == closeFlagReset {
			s.handleRemoteReset(st)
			return nil
		}
		st.endRead(io.EOF)
		if st.isWriteClosed() {
			s.removeStream(st)
		}
		return nil
	default:
		return fmt.Errorf("proxymux: unsupported frame type %d", frame.Type)
	}
}

func (s *Session) handleRemoteOpen(frame Frame) error {
	wantParity := uint32(1) // An accepting endpoint receives odd IDs.
	if s.initiator {
		wantParity = 0 // The initiator uses odd IDs; its peer uses even IDs.
	}
	if frame.StreamID%2 != wantParity {
		return fmt.Errorf("proxymux: peer used the wrong stream ID parity")
	}

	s.mu.Lock()
	if _, exists := s.streams[frame.StreamID]; exists {
		s.mu.Unlock()
		return fmt.Errorf("proxymux: duplicate remote stream ID %d", frame.StreamID)
	}
	if _, closed := s.closedIDs[frame.StreamID]; closed {
		s.mu.Unlock()
		return fmt.Errorf("proxymux: reused remote stream ID %d", frame.StreamID)
	}
	if len(s.streams) >= s.maxStreams {
		s.rememberClosedIDLocked(frame.StreamID)
		s.mu.Unlock()
		_ = s.sendFrame(Frame{Type: TypeOpenError, StreamID: frame.StreamID, Payload: []byte("busy")}, time.Now().Add(s.writeTimeout), nil)
		return nil
	}
	st := newStream(s, frame.StreamID, false)
	s.streams[frame.StreamID] = st
	s.mu.Unlock()

	if s.onOpen == nil {
		_ = s.sendFrame(Frame{Type: TypeOpenError, StreamID: st.id, Payload: []byte("unsupported")}, time.Now().Add(s.writeTimeout), nil)
		st.endRead(errors.New("proxymux: no incoming stream handler"))
		s.removeStream(st)
		return nil
	}

	go s.runRemoteOpen(st, frame.Type, frame.Payload)
	return nil
}

func (s *Session) runRemoteOpen(st *Stream, frameType Type, payload []byte) {
	ctx, cancel := context.WithTimeout(s.ctx, s.openTimeout)
	target, err := s.onOpen(ctx, frameType, payload)
	cancel()
	if err == nil && target == nil {
		err = errors.New("proxymux: open handler returned a nil target")
	}
	if err != nil {
		if target != nil {
			_ = target.Close()
		}
		_ = s.sendFrame(Frame{Type: TypeOpenError, StreamID: st.id, Payload: []byte("open failed")}, time.Now().Add(s.writeTimeout), nil)
		st.mu.Lock()
		st.reset = true
		st.writeClosed = true
		st.mu.Unlock()
		st.endRead(err)
		s.removeStream(st)
		return
	}
	st.mu.Lock()
	if s.isDone() || st.reset {
		st.mu.Unlock()
		_ = target.Close()
		return
	}
	st.target = target
	st.ready = true
	st.openPending = false
	st.mu.Unlock()
	if err := s.sendFrame(Frame{Type: TypeOpenOK, StreamID: st.id}, time.Now().Add(s.writeTimeout), nil); err != nil {
		_ = target.Close()
		st.abort(err)
		return
	}
	go relayStream(st, target)
}

func (s *Session) handleRemoteReset(st *Stream) {
	st.mu.Lock()
	alreadyReset := st.reset
	st.reset = true
	st.writeClosed = true
	target := st.target
	st.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
	st.endRead(net.ErrClosed)
	s.removeStream(st)
	if !alreadyReset {
		_ = s.sendFrame(Frame{Type: TypeClose, StreamID: st.id, Payload: []byte{closeFlagReset}}, time.Now().Add(s.writeTimeout), nil)
	}
}

func (s *Session) getStream(id uint32) (*Stream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.streams[id]
	return st, ok
}

func (s *Session) removeStream(st *Stream) {
	s.mu.Lock()
	if current, ok := s.streams[st.id]; ok && current == st {
		delete(s.streams, st.id)
		s.rememberClosedIDLocked(st.id)
	}
	s.mu.Unlock()
}

func (s *Session) rememberClosedIDLocked(id uint32) {
	if _, exists := s.closedIDs[id]; exists {
		return
	}
	s.closedIDs[id] = struct{}{}
	s.closedOrder = append(s.closedOrder, id)
	if len(s.closedOrder) > 4096 {
		old := s.closedOrder[0]
		s.closedOrder = s.closedOrder[1:]
		delete(s.closedIDs, old)
	}
}

func (s *Session) wasClosed(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.closedIDs[id]
	return ok
}

func (s *Session) localOwnsID(id uint32) bool {
	return (id%2 == 1) == s.initiator
}

func (s *Session) shutdown(err error) {
	s.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		close(s.done)
		s.cancel()
		_ = s.conn.Close()
		s.mu.Lock()
		all := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			all = append(all, st)
		}
		s.streams = make(map[uint32]*Stream)
		s.mu.Unlock()
		for _, st := range all {
			st.markSessionEnd(err)
		}
	})
}

// Stream is one logical bidirectional byte stream. It implements net.Conn;
// CloseWrite supports the half-close behavior needed by ordinary TCP proxying.
type Stream struct {
	session *Session
	id uint32
	localOpen bool
	openPending bool
	ready bool

	openResult chan error
	readCh chan []byte
	target net.Conn
	readDeadlineChanged chan struct{}
	writeDeadlineChanged chan struct{}
	readCloseOnce sync.Once
	readMu sync.Mutex
	writeMu sync.Mutex
	mu sync.Mutex

	pending []byte
	readErr error
	readClosed bool
	writeClosed bool
	reset bool
	readDeadline time.Time
	writeDeadline time.Time
}

func (st *Stream) Read(p []byte) (int, error) {
	st.readMu.Lock()
	defer st.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(st.pending) > 0 {
			n := copy(p, st.pending)
			st.pending = st.pending[n:]
			return n, nil
		}
		st.mu.Lock()
		deadline := st.readDeadline
		deadlineChanged := st.readDeadlineChanged
		st.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(left)
			timeout = timer.C
		}
		select {
		case data, ok := <-st.readCh:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				st.mu.Lock()
				err := st.readErr
				st.mu.Unlock()
				if err == nil {
					err = io.EOF
				}
				return 0, err
			}
			st.pending = data
		case <-st.session.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, st.session.sessionError()
		case <-deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		st.mu.Lock()
		if st.reset || st.writeClosed || !st.ready {
			st.mu.Unlock()
			if written > 0 {
				return written, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		deadline := st.writeDeadline
		st.mu.Unlock()

		n := len(p)
		if n > maxDataSize {
			n = maxDataSize
		}
		payload := append([]byte(nil), p[:n]...)
		if err := st.sendFrame(Frame{Type: TypeData, StreamID: st.id, Payload: payload}); err != nil {
			if written > 0 {
				return written, err
			}
			return 0, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite half-closes this stream's sending direction while leaving the
// response direction readable.
func (st *Stream) CloseWrite() error {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	st.mu.Lock()
	if st.writeClosed || st.reset {
		st.mu.Unlock()
		return nil
	}
	if !st.ready {
		st.mu.Unlock()
		return errors.New("proxymux: stream is not open")
	}
	st.writeClosed = true
	deadline := st.writeDeadline
	st.mu.Unlock()
	if err := st.session.sendFrame(Frame{Type: TypeClose, StreamID: st.id, Payload: []byte{closeFlagWrite}}, deadline, nil); err != nil {
		st.abort(err)
		return err
	}
	if st.isReadClosed() {
		st.session.removeStream(st)
	}
	return nil
}

func (st *Stream) Close() error {
	st.abort(net.ErrClosed)
	return nil
}

func (st *Stream) abort(err error) {
	st.mu.Lock()
	alreadyReset := st.reset
	st.reset = true
	st.writeClosed = true
	target := st.target
	st.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
	st.endRead(err)
	st.session.removeStream(st)
	if !alreadyReset && !st.session.isDone() {
		_ = st.sendFrame(Frame{Type: TypeClose, StreamID: st.id, Payload: []byte{closeFlagReset}})
	}
}

func (st *Stream) pushData(payload []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reset {
		return nil
	}
	if !st.ready || st.readClosed {
		return errors.New("proxymux: DATA received before OPEN_OK or after half-close")
	}
	select {
	case st.readCh <- append([]byte(nil), payload...):
		return nil
	default:
		return errors.New("proxymux: per-stream receive queue is full")
	}
}

func (st *Stream) endRead(err error) {
	st.readCloseOnce.Do(func() {
		st.mu.Lock()
		st.readClosed = true
		st.readErr = err
		close(st.readCh)
		st.mu.Unlock()
	})
}

func (st *Stream) markSessionEnd(err error) {
	st.mu.Lock()
	st.reset = true
	st.writeClosed = true
	target := st.target
	st.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
	st.endRead(err)
	st.resolveOpen(err)
}

func (st *Stream) resolveOpen(err error) {
	select {
	case st.openResult <- err:
	default:
	}
}

func (st *Stream) isReset() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.reset
}

func (st *Stream) isWriteClosed() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.writeClosed
}

func (st *Stream) isReadClosed() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.readClosed
}

func (st *Stream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }

func (st *Stream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline, st.writeDeadline = t, t
	st.notifyDeadlineChangeLocked()
	st.mu.Unlock()
	return nil
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline = t
	if st.readDeadlineChanged != nil {
		close(st.readDeadlineChanged)
	}
	st.readDeadlineChanged = make(chan struct{})
	st.mu.Unlock()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.writeDeadline = t
	if st.writeDeadlineChanged != nil {
		close(st.writeDeadlineChanged)
	}
	st.writeDeadlineChanged = make(chan struct{})
	st.mu.Unlock()
	return nil
}

func (st *Stream) notifyDeadlineChangeLocked() {
	if st.readDeadlineChanged != nil {
		close(st.readDeadlineChanged)
	}
	if st.writeDeadlineChanged != nil {
		close(st.writeDeadlineChanged)
	}
	st.readDeadlineChanged = make(chan struct{})
	st.writeDeadlineChanged = make(chan struct{})
}

func (st *Stream) sendFrame(frame Frame) error {
	for {
		st.mu.Lock()
		deadline := st.writeDeadline
		changed := st.writeDeadlineChanged
		st.mu.Unlock()
		err := st.session.sendFrame(frame, deadline, changed)
		if errors.Is(err, errStreamDeadlineChanged) {
			continue
		}
		return err
	}
}

func relayStream(stream *Stream, target net.Conn) {
	type result struct{ err error }
	results := make(chan result, 2)
	go func() {
		_, err := io.Copy(target, stream)
		if half, ok := target.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else if err != nil {
			_ = target.Close()
		}
		results <- result{err: err}
	}()
	go func() {
		_, err := io.Copy(stream, target)
		if err == nil || errors.Is(err, io.EOF) {
			_ = stream.CloseWrite()
		} else {
			stream.abort(err)
		}
		results <- result{err: err}
	}()

	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil && !errors.Is(r.err, io.EOF) && !errors.Is(r.err, net.ErrClosed) {
			_ = target.Close()
			stream.abort(r.err)
		}
	}
	_ = target.Close()
	_ = stream.Close()
}
