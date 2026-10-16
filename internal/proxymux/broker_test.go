package proxymux

import (
	"context"
	"errors"
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
