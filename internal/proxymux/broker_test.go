package proxymux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSessionBrokerReplacedSessionSurvivesStaleClear(t *testing.T) {
	const replacements = 6
	broker := NewSessionBroker()
	var sessions []*Session
	var latestAccepted <-chan acceptedTarget
	for i := 0; i < replacements; i++ {
		local, _, accepted := newTestSessionPair(t, 4)
		broker.Set(local)
		sessions = append(sessions, local)
		latestAccepted = accepted
		if i > 0 && !sessions[i-1].isDone() {
			t.Fatalf("replacement %d did not close the previous session", i)
		}
	}

	// Simulate delayed teardown callbacks arriving out of order after several reconnects.
	for i := len(sessions) - 2; i >= 0; i-- {
		broker.Clear(sessions[i])
	}
	latest := sessions[len(sessions)-1]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := broker.Open(ctx, TypeOpenDirect, []byte("replacement-target"))
	if err != nil {
		t.Fatalf("Open through latest replacement session: %v", err)
	}
	if stream.session != latest {
		t.Fatal("stale Clear removed the latest session or broker opened on an older session")
	}
	target := awaitTarget(t, latestAccepted, "replacement-target")
	exchangeOnStream(t, stream, target, "after-reconnect", "response-after-reconnect")
}

func TestSessionBrokerOpenHonorsCancellationWithoutSession(t *testing.T) {
	broker := NewSessionBroker()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := broker.Open(ctx, TypeOpenDirect, []byte("waiting-for-session"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Broker.Open() error = %v, want context.DeadlineExceeded", err)
	}
}


// An in-flight broker Open must retry on the replacement session when the
// previous session shuts down before its remote OPEN handler responds.
func TestSessionBrokerOpenRetriesAfterReplacementDuringRemoteOpen(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	oldHandler := func(ctx context.Context, _ Type, _ []byte) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	oldLocal, oldPeer := newSessionPairWithHandlers(t, 4, nil, oldHandler)
	newLocal, _, newAccepted := newTestSessionPair(t, 4)

	broker := NewSessionBroker()
	broker.Set(oldLocal)

	type openResult struct {
		stream *Stream
		err    error
	}
	result := make(chan openResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() {
		stream, err := broker.Open(ctx, TypeOpenDirect, []byte("after-replacement"))
		result <- openResult{stream: stream, err: err}
	}()

	waitForSignal(t, started, "old session remote open handler")
	broker.Set(newLocal)

	var opened *Stream
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("broker Open did not retry on replacement session: %v", got.err)
		}
		opened = got.stream
	case <-time.After(3 * time.Second):
		t.Fatal("broker Open remained blocked after session replacement")
	}
	if opened == nil || opened.session != newLocal {
		t.Fatal("broker Open returned a stream from the replaced session")
	}

	target := awaitTarget(t, newAccepted, "after-replacement")
	exchangeOnStream(t, opened, target, "replacement-request", "replacement-response")
	waitForSignal(t, cancelled, "old session handler cancellation")
	waitForStreamCount(t, oldLocal, 0)
	waitForStreamCount(t, oldPeer, 0)
	if newLocal.isDone() {
		t.Fatal("replacement session was terminated by the old open attempt")
	}
}
