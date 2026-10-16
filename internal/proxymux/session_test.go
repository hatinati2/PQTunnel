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
