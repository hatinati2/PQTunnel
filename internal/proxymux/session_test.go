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
