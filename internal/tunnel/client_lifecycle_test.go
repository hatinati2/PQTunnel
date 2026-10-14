package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type blockingTestDevice struct {
	readStarted chan struct{}
	readExited  chan struct{}
	closed      chan struct{}
	once        sync.Once
}

func newBlockingTestDevice() *blockingTestDevice {
	return &blockingTestDevice{
		readStarted: make(chan struct{}),
		readExited:  make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (d *blockingTestDevice) Read([]byte) (int, error) {
	select {
	case <-d.readStarted:
	default:
		close(d.readStarted)
	}
	<-d.closed
	close(d.readExited)
	return 0, io.ErrClosedPipe
}

func (d *blockingTestDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *blockingTestDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func TestRunClientCancellationClosesDeviceAndUnblocksReader(t *testing.T) {
	dev := newBlockingTestDevice()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunClient(ctx, dev, ClientConfig{
			ServerAddress: "127.0.0.1:1",
			ServerName:    "example.test",
			LocalIP:       netip.MustParseAddr("10.0.0.2"),
			TLSConfig:     &tls.Config{ServerName: "example.test"},
		})
	}()

	select {
	case <-dev.readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not start reading the device")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunClient error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunClient did not return after context cancellation")
	}

	select {
	case <-dev.readExited:
	case <-time.After(2 * time.Second):
		t.Fatal("device reader remained blocked after cancellation")
	}
}
