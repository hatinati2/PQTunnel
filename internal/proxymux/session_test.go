package proxymux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type acceptedTarget struct {
	name string
	conn net.Conn
}

func newSessionPairWithHandlers(t *testing.T, maxStreams int, leftHandler, rightHandler OpenHandler) (*Session, *Session) {
	t.Helper()
	leftConn, rightConn := net.Pipe()
	opts := SessionOptions{
		MaxStreams: maxStreams,
		OpenTimeout: 2 * time.Second,
		WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	}
	leftOpts := opts
	leftOpts.Initiator = true
	leftOpts.OnOpen = leftHandler
	left, err := NewSession(context.Background(), leftConn, leftOpts)
	if err != nil {
		_ = leftConn.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(left): %v", err)
	}
	rightOpts := opts
	rightOpts.Initiator = false
	rightOpts.OnOpen = rightHandler
	right, err := NewSession(context.Background(), rightConn, rightOpts)
	if err != nil {
		_ = left.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(right): %v", err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return left, right
}

func newTCPConnPair() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	server, err := listener.Accept()
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return client, server, nil
}

func waitForSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func newTestSessionPair(t *testing.T, maxStreams int) (*Session, *Session, <-chan acceptedTarget) {
	t.Helper()
	leftConn, rightConn := net.Pipe()
	accepted := make(chan acceptedTarget, 8)

	openHandler := func(_ context.Context, typ Type, payload []byte) (net.Conn, error) {
		if typ != TypeOpenDirect && typ != TypeOpenReverse {
			return nil, errors.New("unexpected open type")
		}
		serverSide, testSide := net.Pipe()
		accepted <- acceptedTarget{name: string(payload), conn: testSide}
		return serverSide, nil
	}
	left, err := NewSession(context.Background(), leftConn, SessionOptions{
		Initiator: true, MaxStreams: maxStreams,
		OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
		OnOpen: openHandler,
	})
	if err != nil {
		_ = leftConn.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(left): %v", err)
	}
	right, err := NewSession(context.Background(), rightConn, SessionOptions{
		Initiator: false, MaxStreams: maxStreams,
		OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
		OnOpen: openHandler,
	})
	if err != nil {
		_ = left.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(right): %v", err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return left, right, accepted
}

func awaitTarget(t *testing.T, accepted <-chan acceptedTarget, want string) net.Conn {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case target := <-accepted:
			if target.name == want {
				t.Cleanup(func() { _ = target.conn.Close() })
				_ = target.conn.SetDeadline(time.Now().Add(2 * time.Second))
				return target.conn
			}
			_ = target.conn.Close()
		case <-timer.C:
			t.Fatalf("timed out waiting for target %q", want)
			return nil
		}
	}
}

func exchangeOnStream(t *testing.T, stream *Stream, target net.Conn, request, response string) {
	t.Helper()
	_ = target.SetDeadline(time.Now().Add(2 * time.Second))
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))

	writeDone := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte(request))
		writeDone <- err
	}()
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(target, gotRequest); err != nil {
		t.Fatalf("target read request: %v", err)
	}
	if !bytes.Equal(gotRequest, []byte(request)) {
		t.Fatalf("target received %q, want %q", gotRequest, request)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("stream write: %v", err)
	}

	writeResponseDone := make(chan error, 1)
	go func() {
		_, err := target.Write([]byte(response))
		writeResponseDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(stream, gotResponse); err != nil {
		t.Fatalf("stream read response: %v", err)
	}
	if !bytes.Equal(gotResponse, []byte(response)) {
		t.Fatalf("stream received %q, want %q", gotResponse, response)
	}
	if err := <-writeResponseDone; err != nil {
		t.Fatalf("target write response: %v", err)
	}
}

func TestSessionMultiplexesDirectAndReverseStreams(t *testing.T) {
	left, _, accepted := newTestSessionPair(t, 8)

	direct, err := left.Open(TypeOpenDirect, []byte("direct:127.0.0.1:8080"))
	if err != nil {
		t.Fatalf("open Direct stream: %v", err)
	}
	reverse, err := left.Open(TypeOpenReverse, []byte("reverse:web"))
	if err != nil {
		t.Fatalf("open Reverse stream: %v", err)
	}
	directTarget := awaitTarget(t, accepted, "direct:127.0.0.1:8080")
	reverseTarget := awaitTarget(t, accepted, "reverse:web")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		exchangeOnStream(t, direct, directTarget, "direct-request", "direct-response")
	}()
	go func() {
		defer wg.Done()
		exchangeOnStream(t, reverse, reverseTarget, "reverse-request", "reverse-response")
	}()
	wg.Wait()
}

func TestSessionRejectsOpenWhenStreamLimitReached(t *testing.T) {
	left, _, accepted := newTestSessionPair(t, 1)

	first, err := left.Open(TypeOpenDirect, []byte("direct:first"))
	if err != nil {
		t.Fatalf("open first stream: %v", err)
	}
	_ = awaitTarget(t, accepted, "direct:first")

	if _, err := left.Open(TypeOpenReverse, []byte("reverse:second")); err == nil {
		t.Fatal("second stream unexpectedly opened beyond the configured limit")
	}
	_ = first.Close()
}

func TestSessionRejectsRemoteOpenWithoutHandler(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, err := NewSession(context.Background(), leftConn, SessionOptions{
		Initiator: true, OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewSession(context.Background(), rightConn, SessionOptions{
		Initiator: false, OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	if _, err := left.Open(TypeOpenDirect, []byte("disallowed:target")); err == nil {
		t.Fatal("open unexpectedly succeeded without a remote handler")
	}
	if left.isDone() || right.isDone() {
		t.Fatal("a rejected stream incorrectly terminated the shared session")
	}
}


// waitForStreamCount waits until a session releases all streams expected by a test.
func waitForStreamCount(t *testing.T, session *Session, want int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		session.mu.Lock()
		got := len(session.streams)
		session.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("session retained %d streams, want %d", got, want)
		case <-ticker.C:
		}
	}
}

// A vanished local target must not leave its logical stream in either session.
func TestSessionReapsStreamWhenTargetClosesDuringTraffic(t *testing.T) {
	left, right, accepted := newTestSessionPair(t, 8)
	stream, err := left.Open(TypeOpenDirect, []byte("reap:target"))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	target := awaitTarget(t, accepted, "reap:target")

	writeDone := make(chan error, 1)
	go func() {
		_, err := stream.Write(bytes.Repeat([]byte("x"), 64*1024))
		writeDone <- err
	}()

	// The target is deliberately not read: its peer relay may be blocked
	// writing buffered data when the local TCP connection disappears.
	time.Sleep(25 * time.Millisecond)
	if err := target.Close(); err != nil {
		t.Fatalf("close target: %v", err)
	}

	select {
	case <-writeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not unblock after the target closed")
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
}


// Half-closing one stream direction must preserve the other direction until
// the peer has sent its response and half-closed as well.
func TestSessionHalfClosePreservesResponse(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	rightHandler := func(_ context.Context, typ Type, _ []byte) (net.Conn, error) {
		if typ != TypeOpenDirect {
			return nil, errors.New("unexpected stream type")
		}
		client, server, err := newTCPConnPair()
		if err != nil {
			return nil, err
		}
		accepted <- client
		return server, nil
	}
	left, right := newSessionPairWithHandlers(t, 4, nil, rightHandler)
	stream, err := left.Open(TypeOpenDirect, []byte("half-close"))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	var target net.Conn
	select {
	case target = <-accepted:
		t.Cleanup(func() { _ = target.Close() })
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP test target")
	}

	const request = "request-before-fin"
	const response = "response-after-fin"
	if _, err := stream.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("half-close stream write side: %v", err)
	}
	gotRequest, err := io.ReadAll(target)
	if err != nil {
		t.Fatalf("read request until remote FIN: %v", err)
	}
	if string(gotRequest) != request {
		t.Fatalf("target received %q, want %q", gotRequest, request)
	}
	if _, err := target.Write([]byte(response)); err != nil {
		t.Fatalf("write response after receiving FIN: %v", err)
	}
	if err := target.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close target write side: %v", err)
	}
	gotResponse, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read response until stream EOF: %v", err)
	}
	if string(gotResponse) != response {
		t.Fatalf("stream received %q, want %q", gotResponse, response)
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
	if left.isDone() || right.isDone() {
		t.Fatal("half-close incorrectly terminated the shared session")
	}
}

// Cancelling a local open must cancel the remote target dial/open operation and
// remove both logical streams without taking down the shared transport.
func TestSessionOpenContextCancellationCancelsRemoteHandler(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	rightHandler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	left, right := newSessionPairWithHandlers(t, 4, nil, rightHandler)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := left.OpenContext(ctx, TypeOpenDirect, []byte("cancel-me"))
		result <- err
	}()
	waitForSignal(t, started, "remote open handler")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OpenContext did not return after cancellation")
	}
	waitForSignal(t, cancelled, "remote open handler cancellation")
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
	if left.isDone() || right.isDone() {
		t.Fatal("cancelling one open incorrectly terminated the shared session")
	}
}

// A blocked target makes the peer receive queue fill. The affected stream
// must be reset and reaped while unrelated streams/session state stay alive.
func TestSessionReceiveQueueSaturationReapsOnlyAffectedStream(t *testing.T) {
	left, right, accepted := newTestSessionPair(t, 4)
	stream, err := left.Open(TypeOpenDirect, []byte("queue-saturation"))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	var target net.Conn
	select {
	case item := <-accepted:
		if item.name != "queue-saturation" {
			t.Fatalf("unexpected target %q", item.name)
		}
		target = item.conn
		t.Cleanup(func() { _ = target.Close() })
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for target")
	}

	writeDone := make(chan error, 1)
	payload := bytes.Repeat([]byte("q"), maxDataSize*(streamReadQueueFrames+4))
	go func() {
		_, err := stream.Write(payload)
		writeDone <- err
	}()
	select {
	case <-writeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("writer remained blocked after bounded receive queue filled")
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
	if left.isDone() || right.isDone() {
		t.Fatal("queue saturation terminated the shared session instead of resetting one stream")
	}
}


// Closing the transport while a remote OPEN handler is blocked must cancel
// the handler and release the local OpenContext caller without waiting for its
// open timeout.
func TestSessionShutdownCancelsPendingRemoteOpen(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	rightHandler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	left, right := newSessionPairWithHandlers(t, 4, nil, rightHandler)

	result := make(chan error, 1)
	go func() {
		_, err := left.OpenContext(context.Background(), TypeOpenDirect, []byte("shutdown-pending-open"))
		result <- err
	}()
	waitForSignal(t, started, "blocked remote open handler")

	if err := left.Close(); err != nil {
		t.Fatalf("close session during pending open: %v", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("OpenContext unexpectedly succeeded after session shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenContext remained blocked after session shutdown")
	}
	waitForSignal(t, cancelled, "remote handler cancellation after session shutdown")
	deadline := time.Now().Add(2 * time.Second)
	for !right.isDone() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !right.isDone() {
		t.Fatal("peer session did not observe transport shutdown")
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
}

// Repeated transport shutdown during concurrent stream opens must not strand
// callers or leave logical streams registered after the session is gone.
func TestSessionShutdownDuringConcurrentOpensReapsAllStreams(t *testing.T) {
	const opens = 32
	started := make(chan struct{}, opens)
	cancelled := make(chan struct{}, opens)
	rightHandler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return nil, ctx.Err()
	}
	left, right := newSessionPairWithHandlers(t, opens, nil, rightHandler)

	start := make(chan struct{})
	results := make(chan error, opens)
	var wg sync.WaitGroup
	wg.Add(opens)
	for i := 0; i < opens; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := left.OpenContext(ctx, TypeOpenDirect, []byte("shutdown-race"))
			results <- err
		}(i)
	}
	close(start)

	for i := 0; i < opens; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d remote handlers started before timeout", i)
		}
	}
	if err := left.Close(); err != nil {
		t.Fatalf("close session during concurrent opens: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent OpenContext callers were stranded by session shutdown")
	}
	close(results)
	for err := range results {
		if err == nil {
			t.Fatal("OpenContext unexpectedly succeeded while session was shutting down")
		}
	}
	for i := 0; i < opens; i++ {
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d remote handlers observed cancellation", i)
		}
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
}


// A late OPEN_OK for a stream reset by local cancellation must trigger a
// stream-local reset, not terminate the otherwise healthy session.
func TestSessionLateOpenOKAfterCancellationResetsOnlyStream(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true,
		MaxStreams: 4,
		OpenTimeout: time.Second,
		WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, openErr := session.OpenContext(ctx, TypeOpenDirect, []byte("late-open-ok"))
		result <- openErr
	}()

	openFrame, err := ReadFrame(peerConn)
	if err != nil {
		cancel()
		t.Fatalf("read OPEN request: %v", err)
	}
	if openFrame.Type != TypeOpenDirect || openFrame.StreamID == 0 {
		cancel()
		t.Fatalf("unexpected initial frame: %#v", openFrame)
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenContext did not return after cancellation")
	}

	reset, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read cancellation reset: %v", err)
	}
	if reset.Type != TypeClose || reset.StreamID != openFrame.StreamID ||
		len(reset.Payload) != 1 || reset.Payload[0] != closeFlagReset {
		t.Fatalf("unexpected cancellation frame: %#v", reset)
	}

	if err := WriteFrame(peerConn, Frame{Type: TypeOpenOK, StreamID: openFrame.StreamID}); err != nil {
		t.Fatalf("write delayed OPEN_OK: %v", err)
	}
	lateReset, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read reset for delayed OPEN_OK: %v", err)
	}
	if lateReset.Type != TypeClose || lateReset.StreamID != openFrame.StreamID ||
		len(lateReset.Payload) != 1 || lateReset.Payload[0] != closeFlagReset {
		t.Fatalf("unexpected response to delayed OPEN_OK: %#v", lateReset)
	}

	if session.isDone() {
		t.Fatal("late OPEN_OK for a cancelled stream terminated the shared session")
	}
	waitForStreamCount(t, session, 0)
}


// DATA received before OPEN_OK is a stream-local protocol violation. It must
// reset that stream and promptly release the waiting OpenContext caller
// instead of leaving it blocked until the full open timeout.
func TestSessionDataBeforeOpenOKReleasesOpenCaller(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true,
		MaxStreams: 4,
		OpenTimeout: 4 * time.Second,
		WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	type openResult struct {
		stream *Stream
		err    error
	}
	result := make(chan openResult, 1)
	go func() {
		stream, openErr := session.OpenContext(
			context.Background(), TypeOpenDirect, []byte("early-data"),
		)
		result <- openResult{stream: stream, err: openErr}
	}()

	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read OPEN request: %v", err)
	}
	if request.Type != TypeOpenDirect || request.StreamID == 0 {
		t.Fatalf("unexpected OPEN frame: %#v", request)
	}
	if err := WriteFrame(peerConn, Frame{
		Type: TypeData, StreamID: request.StreamID, Payload: []byte("too-early"),
	}); err != nil {
		t.Fatalf("write DATA before OPEN_OK: %v", err)
	}

	reset, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read stream reset: %v", err)
	}
	if reset.Type != TypeClose || reset.StreamID != request.StreamID ||
		len(reset.Payload) != 1 || reset.Payload[0] != closeFlagReset {
		t.Fatalf("unexpected response to premature DATA: %#v", reset)
	}

	select {
	case got := <-result:
		if got.err == nil {
			t.Fatal("OpenContext unexpectedly succeeded after premature DATA")
		}
		if got.stream != nil {
			t.Fatal("OpenContext returned a stream after protocol reset")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("OpenContext remained blocked after its stream was reset")
	}
	if session.isDone() {
		t.Fatal("premature DATA on one stream terminated the shared session")
	}
	waitForStreamCount(t, session, 0)
}


// CLOSE before OPEN_OK must reset only the pending stream and release the
// OpenContext caller immediately, rather than leaving it until OpenTimeout.
func TestSessionCloseBeforeOpenOKReleasesOpenCaller(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true, MaxStreams: 4,
		OpenTimeout: 4 * time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	result := make(chan error, 1)
	go func() {
		_, openErr := session.OpenContext(context.Background(), TypeOpenDirect, []byte("early-close"))
		result <- openErr
	}()
	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read OPEN request: %v", err)
	}
	if err := WriteFrame(peerConn, Frame{
		Type: TypeClose, StreamID: request.StreamID, Payload: []byte{closeFlagWrite},
	}); err != nil {
		t.Fatalf("write CLOSE before OPEN_OK: %v", err)
	}
	reset, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read stream reset: %v", err)
	}
	if reset.Type != TypeClose || reset.StreamID != request.StreamID ||
		len(reset.Payload) != 1 || reset.Payload[0] != closeFlagReset {
		t.Fatalf("unexpected response to premature CLOSE: %#v", reset)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("OpenContext unexpectedly succeeded after premature CLOSE")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("OpenContext remained blocked after premature CLOSE")
	}
	if session.isDone() {
		t.Fatal("premature CLOSE on one stream terminated the shared session")
	}
	waitForStreamCount(t, session, 0)
}

// OPEN_ERROR is only valid while the stream is pending. A late OPEN_ERROR
// after OPEN_OK is a protocol-order violation and must terminate the session.
func TestSessionRejectsOpenErrorAfterOpenOK(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true, MaxStreams: 4,
		OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	result := make(chan error, 1)
	go func() {
		_, openErr := session.OpenContext(context.Background(), TypeOpenDirect, []byte("open-error-order"))
		result <- openErr
	}()
	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read OPEN request: %v", err)
	}
	if err := WriteFrame(peerConn, Frame{Type: TypeOpenOK, StreamID: request.StreamID}); err != nil {
		t.Fatalf("write OPEN_OK: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("OpenContext before late OPEN_ERROR: %v", err)
	}
	if err := WriteFrame(peerConn, Frame{
		Type: TypeOpenError, StreamID: request.StreamID, Payload: []byte("late error"),
	}); err != nil {
		t.Fatalf("write delayed OPEN_ERROR: %v", err)
	}

	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("out-of-order OPEN_ERROR did not terminate the session")
	}
	if session.Err() == nil {
		t.Fatal("session ended without recording a protocol error")
	}
}

// A full outbound queue must respect the stream write deadline without
// terminating the shared session. The peer intentionally stops reading after
// OPEN_OK so the transport writer blocks on net.Pipe.
func TestStreamWriteDeadlineWhenOutboundQueueSaturates(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true, MaxStreams: 4,
		OpenTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	result := make(chan *Stream, 1)
	openErr := make(chan error, 1)
	go func() {
		stream, err := session.OpenContext(context.Background(), TypeOpenDirect, []byte("write-deadline"))
		if err != nil {
			openErr <- err
			return
		}
		result <- stream
	}()
	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read OPEN request: %v", err)
	}
	if err := WriteFrame(peerConn, Frame{Type: TypeOpenOK, StreamID: request.StreamID}); err != nil {
		t.Fatalf("write OPEN_OK: %v", err)
	}

	var stream *Stream
	select {
	case stream = <-result:
	case err := <-openErr:
		t.Fatalf("OpenContext: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OPEN_OK")
	}
	if err := stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	payload := bytes.Repeat([]byte("w"), maxDataSize*258)
	n, err := stream.Write(payload)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write error = %v, want os.ErrDeadlineExceeded (wrote %d bytes)", err, n)
	}
	if n <= 0 || n >= len(payload) {
		t.Fatalf("Write returned partial count %d for payload length %d", n, len(payload))
	}
	if session.isDone() {
		t.Fatal("a single stream write deadline terminated the shared session")
	}
}


// Stream ID allocation must wrap without using zero, colliding with a live
// stream, or reusing one of the recently closed IDs.
func TestSessionAllocateIDWraparoundSkipsActiveAndRecentlyClosedIDs(t *testing.T) {
	left, right, _ := newTestSessionPair(t, 8)
	maxID := ^uint32(0)
	tests := []struct {
		name     string
		session  *Session
		nextID   uint32
		closed   []uint32
		activeID uint32
		wantID   uint32
	}{
		{
			name: "initiator odd IDs",
			session: left,
			nextID: maxID,
			closed: []uint32{maxID, 1},
			activeID: 3,
			wantID: 5,
		},
		{
			name: "acceptor even IDs",
			session: right,
			nextID: maxID - 1,
			closed: []uint32{maxID - 1, 2},
			activeID: 4,
			wantID: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.session
			s.mu.Lock()
			s.nextID = tt.nextID
			for _, id := range tt.closed {
				s.closedIDs[id] = struct{}{}
			}
			s.streams[tt.activeID] = newStream(s, tt.activeID, s.initiator)
			got, err := s.allocateIDLocked()
			s.mu.Unlock()

			if err != nil {
				t.Fatalf("allocateIDLocked() error = %v", err)
			}
			if got != tt.wantID {
				t.Fatalf("allocateIDLocked() = %d, want %d", got, tt.wantID)
			}
			if got == 0 || (got%2 == 1) != s.initiator {
				t.Fatalf("allocated stream ID %d has invalid parity for initiator=%t", got, s.initiator)
			}
		})
	}
}

// The recently-closed ID cache must remain bounded as streams churn.
func TestSessionClosedIDCacheRemainsBounded(t *testing.T) {
	left, _, _ := newTestSessionPair(t, 4)
	left.mu.Lock()
	for id := uint32(1); id <= 4097; id++ {
		left.rememberClosedIDLocked(id)
	}
	count := len(left.closedIDs)
	_, firstRetained := left.closedIDs[1]
	_, newestRetained := left.closedIDs[4097]
	orderLen := len(left.closedOrder)
	left.mu.Unlock()

	if count != 4096 || orderLen != 4096 {
		t.Fatalf("closed ID cache sizes = map:%d order:%d, want 4096 each", count, orderLen)
	}
	if firstRetained {
		t.Fatal("oldest closed ID was not evicted from the bounded cache")
	}
	if !newestRetained {
		t.Fatal("newest closed ID was unexpectedly evicted")
	}
}

// OPEN_OK is a one-time transition. A duplicate success response for the same
// still-open stream is a protocol violation and must close the session.
func TestSessionRejectsDuplicateOpenOK(t *testing.T) {
	localConn, peerConn := net.Pipe()
	session, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true, MaxStreams: 4,
		OpenTimeout: time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})

	type openResult struct {
		stream *Stream
		err    error
	}
	result := make(chan openResult, 1)
	go func() {
		stream, openErr := session.OpenContext(context.Background(), TypeOpenDirect, []byte("duplicate-open-ok"))
		result <- openResult{stream: stream, err: openErr}
	}()

	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("read OPEN request: %v", err)
	}
	if err := WriteFrame(peerConn, Frame{Type: TypeOpenOK, StreamID: request.StreamID}); err != nil {
		t.Fatalf("write first OPEN_OK: %v", err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.stream == nil {
			t.Fatalf("OpenContext after first OPEN_OK = (%v, %v)", got.stream, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenContext did not complete after first OPEN_OK")
	}

	if err := WriteFrame(peerConn, Frame{Type: TypeOpenOK, StreamID: request.StreamID}); err != nil {
		t.Fatalf("write duplicate OPEN_OK: %v", err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("duplicate OPEN_OK did not terminate the session")
	}
	if session.Err() == nil {
		t.Fatal("duplicate OPEN_OK terminated the session without a protocol error")
	}
	waitForStreamCount(t, session, 0)
}

// A handler can ignore cancellation and return a connected target after its
// open deadline. The session must reject that late target, close it, and reap
// every stream. Repeat the scenario to catch target leaks across timeouts.
func TestSessionLateTargetAfterRepeatedOpenTimeoutsIsClosed(t *testing.T) {
	const attempts = 3
	localConn, peerConn := net.Pipe()
	targetPeers := make(chan net.Conn, attempts)
	handlerTimedOut := make(chan struct{}, attempts)
	releaseHandler := make(chan struct{}, attempts)

	handler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		target, observer := net.Pipe()
		targetPeers <- observer
		<-ctx.Done()
		handlerTimedOut <- struct{}{}
		<-releaseHandler
		return target, nil
	}
	local, err := NewSession(context.Background(), localConn, SessionOptions{
		Initiator: true, MaxStreams: 8,
		OpenTimeout: 3 * time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = localConn.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession(local): %v", err)
	}
	remote, err := NewSession(context.Background(), peerConn, SessionOptions{
		Initiator: false, MaxStreams: 8,
		OpenTimeout: 75 * time.Millisecond, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour, OnOpen: handler,
	})
	if err != nil {
		_ = local.Close()
		_ = peerConn.Close()
		t.Fatalf("NewSession(remote): %v", err)
	}
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})

	for i := 0; i < attempts; i++ {
		type result struct {
			stream *Stream
			err    error
		}
		opened := make(chan result, 1)
		go func() {
			stream, openErr := local.OpenContext(context.Background(), TypeOpenDirect, []byte("late-target"))
			opened <- result{stream: stream, err: openErr}
		}()

		var targetPeer net.Conn
		select {
		case targetPeer = <-targetPeers:
			t.Cleanup(func() { _ = targetPeer.Close() })
		case <-time.After(2 * time.Second):
			t.Fatalf("attempt %d: handler did not create target", i)
		}
		select {
		case <-handlerTimedOut:
		case <-time.After(time.Second):
			t.Fatalf("attempt %d: remote open context did not expire", i)
		}
		releaseHandler <- struct{}{}

		select {
		case got := <-opened:
			if got.err == nil || got.stream != nil {
				t.Fatalf("attempt %d: late target unexpectedly opened stream (%v, %v)", i, got.stream, got.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("attempt %d: OpenContext remained blocked after remote timeout", i)
		}

		closed := make(chan error, 1)
		go func(conn net.Conn) {
			var one [1]byte
			_, readErr := conn.Read(one[:])
			closed <- readErr
		}(targetPeer)
		select {
		case readErr := <-closed:
			if readErr == nil {
				t.Fatalf("attempt %d: late target connection remained open", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("attempt %d: target connection was leaked after open timeout", i)
		}

		waitForStreamCount(t, local, 0)
		waitForStreamCount(t, remote, 0)
		if local.isDone() || remote.isDone() {
			t.Fatalf("attempt %d: one expired open terminated the shared session", i)
		}
	}
}


// Inbound OPEN floods must not create more handler workers or registered
// streams than MaxStreams allows, and transport shutdown must reap all of them.
func TestSessionInboundOpenFloodIsBoundedAndReaped(t *testing.T) {
	const (
		incomingLimit = 8
		openAttempts  = 32
	)
	started := make(chan struct{}, openAttempts)
	cancelled := make(chan struct{}, openAttempts)
	handler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return nil, ctx.Err()
	}

	leftConn, rightConn := net.Pipe()
	left, err := NewSession(context.Background(), leftConn, SessionOptions{
		Initiator: true, MaxStreams: openAttempts,
		OpenTimeout: 5 * time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour,
	})
	if err != nil {
		_ = leftConn.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(left): %v", err)
	}
	right, err := NewSession(context.Background(), rightConn, SessionOptions{
		Initiator: false, MaxStreams: incomingLimit,
		OpenTimeout: 5 * time.Second, WriteTimeout: time.Second,
		KeepAliveInterval: time.Hour, OnOpen: handler,
	})
	if err != nil {
		_ = left.Close()
		_ = rightConn.Close()
		t.Fatalf("NewSession(right): %v", err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	type openResult struct {
		stream *Stream
		err    error
	}
	results := make(chan openResult, openAttempts)
	start := make(chan struct{})
	for i := 0; i < openAttempts; i++ {
		go func(i int) {
			<-start
			stream, openErr := left.OpenContext(
				context.Background(), TypeOpenDirect, []byte{byte(i + 1)},
			)
			results <- openResult{stream: stream, err: openErr}
		}(i)
	}
	close(start)

	for i := 0; i < incomingLimit; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d remote handlers started; want %d", i, incomingLimit)
		}
	}

	rejected := 0
	for rejected < openAttempts-incomingLimit {
		select {
		case got := <-results:
			if got.err == nil || got.stream != nil {
				t.Fatalf("over-limit OPEN unexpectedly succeeded: stream=%v err=%v", got.stream, got.err)
			}
			rejected++
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d over-limit opens were rejected; want %d", rejected, openAttempts-incomingLimit)
		}
	}

	right.mu.Lock()
	active := len(right.streams)
	right.mu.Unlock()
	if active != incomingLimit {
		t.Fatalf("registered inbound streams = %d, want exactly %d", active, incomingLimit)
	}
	if len(started) != 0 {
		t.Fatalf("handler workers started beyond MaxStreams: %d extra starts", len(started))
	}

	if err := left.Close(); err != nil {
		t.Fatalf("close initiating session: %v", err)
	}
	for i := 0; i < incomingLimit; i++ {
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d handler workers observed shutdown", i, incomingLimit)
		}
	}
	for i := 0; i < incomingLimit; i++ {
		select {
		case got := <-results:
			if got.err == nil || got.stream != nil {
				t.Fatalf("pending open unexpectedly succeeded during shutdown: stream=%v err=%v", got.stream, got.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d pending open callers returned after shutdown", i)
		}
	}
	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
}
