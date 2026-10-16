package proxymux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
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
