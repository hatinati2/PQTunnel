package proxymux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A single authenticated session must carry many independent TCP flows without
// mixing payloads or leaving logical streams behind after callers close them.
func TestSessionStressConcurrentStreamsDoNotCrossTalk(t *testing.T) {
	const (
		streamCount = 48
		payloadSize = 64 * 1024
	)

	accepted := make(chan acceptedTarget, streamCount)
	handler := func(ctx context.Context, typ Type, payload []byte) (net.Conn, error) {
		if typ != TypeOpenDirect {
			return nil, errors.New("unexpected stream type")
		}
		client, server, err := newTCPConnPair()
		if err != nil {
			return nil, err
		}
		select {
		case accepted <- acceptedTarget{name: string(payload), conn: client}:
			return server, nil
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		}
	}

	left, right := newSessionPairWithHandlers(t, streamCount, nil, handler)
	streams := make([]*Stream, streamCount)
	names := make([]string, streamCount)
	for i := 0; i < streamCount; i++ {
		names[i] = fmt.Sprintf("stress-%02d", i)
		stream, err := left.Open(TypeOpenDirect, []byte(names[i]))
		if err != nil {
			t.Fatalf("open stream %s: %v", names[i], err)
		}
		streams[i] = stream
	}

	targets := make(map[string]net.Conn, streamCount)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for i := 0; i < streamCount; i++ {
		select {
		case target := <-accepted:
			if _, exists := targets[target.name]; exists {
				_ = target.conn.Close()
				t.Fatalf("duplicate target for %q", target.name)
			}
			targets[target.name] = target.conn
			t.Cleanup(func() { _ = target.conn.Close() })
		case <-timer.C:
			t.Fatalf("received %d of %d targets", len(targets), streamCount)
		}
	}

	var wg sync.WaitGroup
	wg.Add(streamCount)
	for i := 0; i < streamCount; i++ {
		i := i
		go func() {
			defer wg.Done()
			request := stressPayload("request", i, payloadSize)
			response := stressPayload("response", i, payloadSize/2)
			exchangeOnStream(t, streams[i], targets[names[i]], request, response)
			_ = streams[i].Close()
		}()
	}
	wg.Wait()

	waitForStreamCount(t, left, 0)
	waitForStreamCount(t, right, 0)
	if left.isDone() || right.isDone() {
		t.Fatal("concurrent stream cleanup terminated the shared session")
	}
}

func stressPayload(label string, streamIndex, size int) string {
	prefix := fmt.Sprintf("%s-%02d-", label, streamIndex)
	return strings.Repeat(prefix, size/len(prefix)+1)[:size]
}
