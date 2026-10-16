package proxymux

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionBrokerReplacedSessionSurvivesStaleClear(t *testing.T) {
	oldLocal, _, _ := newTestSessionPair(t, 4)
	newLocal, _, accepted := newTestSessionPair(t, 4)
	broker := NewSessionBroker()
	broker.Set(oldLocal)
	broker.Set(newLocal)

	if !oldLocal.isDone() {
		t.Fatal("replacing a broker session did not close the previous session")
	}
	// A slow/late goroutine belonging to the old session must not clear the new one.
	broker.Clear(oldLocal)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := broker.Open(ctx, TypeOpenDirect, []byte("replacement-target"))
	if err != nil {
		t.Fatalf("Open through replacement session: %v", err)
	}
	if stream.session != newLocal {
		t.Fatal("broker opened a stream on a stale session")
	}
	target := awaitTarget(t, accepted, "replacement-target")
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
