package proxymux

import (
	"context"
	"errors"
	"sync"
)

// SessionBroker tracks the current authenticated transport session across
// reconnects. Call Set when a fully authenticated session is ready and Clear
// when that exact session ends.
type SessionBroker struct {
	mu      sync.Mutex
	current *Session
	changed chan struct{}
}

// NewSessionBroker returns an empty broker.
func NewSessionBroker() *SessionBroker {
	return &SessionBroker{changed: make(chan struct{})}
}

// Set publishes a new session and closes the previous session if it differs.
func (b *SessionBroker) Set(session *Session) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.ensureLocked()
	if b.current == session {
		b.mu.Unlock()
		return
	}
	old := b.current
	b.current = session
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
	if old != nil && old != session {
		_ = old.Close()
	}
}

// Clear removes session only if it is still the broker's current session.
// This compare prevents an old reconnect worker from clearing a newer session.
func (b *SessionBroker) Clear(session *Session) {
	if b == nil || session == nil {
		return
	}
	b.mu.Lock()
	b.ensureLocked()
	if b.current == session {
		b.current = nil
		close(b.changed)
		b.changed = make(chan struct{})
	}
	b.mu.Unlock()
}

// Open waits for an active authenticated session and opens a logical stream.
// If the transport dies while opening, it waits for the reconnect worker to
// publish the next session. A remote OPEN_ERROR is returned to the caller.
func (b *SessionBroker) Open(ctx context.Context, frameType Type, payload []byte) (*Stream, error) {
	if b == nil {
		return nil, errors.New("proxymux: session broker is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		b.mu.Lock()
		b.ensureLocked()
		session, changed := b.current, b.changed
		b.mu.Unlock()

		if session != nil && !session.isDone() {
			stream, err := session.OpenContext(ctx, frameType, payload)
			if err == nil {
				return stream, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if session.isDone() {
				b.Clear(session)
				continue
			}
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (b *SessionBroker) ensureLocked() {
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
}
