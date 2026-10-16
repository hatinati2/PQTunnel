package proxymux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseTCPPortSet(t *testing.T) {
	ports, err := ParseTCPPortSet("80,443,8000-8002")
	if err != nil {
		t.Fatalf("ParseTCPPortSet() error = %v", err)
	}
	for _, p := range []uint16{80, 443, 8000, 8001, 8002} {
		if _, ok := ports[p]; !ok {
			t.Fatalf("port %d missing from parsed set", p)
		}
	}
	for _, value := range []string{"", "0", "65536", "443-", "9000-8000", "1-5000", "80,,443"} {
		if _, err := ParseTCPPortSet(value); err == nil {
			t.Fatalf("ParseTCPPortSet(%q) unexpectedly succeeded", value)
		}
	}
}

func TestParseNamedAddresses(t *testing.T) {
	got, err := ParseNamedAddresses("web=127.0.0.1:8080,ssh=[::1]:22")
	if err != nil {
		t.Fatalf("ParseNamedAddresses() error = %v", err)
	}
	if got["web"] != "127.0.0.1:8080" || got["ssh"] != "[::1]:22" {
		t.Fatalf("unexpected mappings: %#v", got)
	}
	for _, value := range []string{"bad", "web=", "web=127.0.0.1:0", "web=127.0.0.1:80,web=127.0.0.1:81", "../bad=127.0.0.1:80"} {
		if _, err := ParseNamedAddresses(value); err == nil {
			t.Fatalf("ParseNamedAddresses(%q) unexpectedly succeeded", value)
		}
	}
}

func TestDirectTargetHandlerRequiresAllowedPublicTarget(t *testing.T) {
	handler := NewDirectTargetHandler(map[uint16]struct{}{443: {}})
	if _, err := handler(context.Background(), TypeOpenDirect, []byte("127.0.0.1:443")); err == nil {
		t.Fatal("private target was unexpectedly allowed")
	}
	if _, err := handler(context.Background(), TypeOpenDirect, []byte("example.com:8443")); err == nil {
		t.Fatal("unlisted port was unexpectedly allowed")
	}
	for _, target := range []string{
		"[::2]:443",
		"[64:ff9b::a9fe:a9fe]:443",
		"[100:0:0:1::1]:443",
		"[3ffe::1]:443",
		"[3fff::1]:443",
		"[5f00::1]:443",
		"[fec0::1]:443",
	} {
		if _, err := handler(context.Background(), TypeOpenDirect, []byte(target)); err == nil {
			t.Fatalf("reserved IPv6 destination %q was unexpectedly allowed", target)
		}
	}
	if _, err := handler(context.Background(), TypeOpenReverse, []byte("web")); err == nil {
		t.Fatal("Direct handler accepted a Reverse request")
	}
}

func TestReverseTargetHandlerUsesOnlyConfiguredNames(t *testing.T) {
	handler := NewReverseTargetHandler(map[string]string{"web": "127.0.0.1:80"})
	if _, err := handler(context.Background(), TypeOpenReverse, []byte("unknown")); err == nil {
		t.Fatal("unconfigured reverse target was unexpectedly allowed")
	}
	if _, err := handler(context.Background(), TypeOpenDirect, []byte("127.0.0.1:80")); err == nil {
		t.Fatal("Reverse handler accepted a Direct request")
	}
}

func TestListenSOCKS5RejectsWildcardAddress(t *testing.T) {
	if _, err := ListenSOCKS5("0.0.0.0:1080"); err == nil {
		t.Fatal("SOCKS5 listener unexpectedly accepted a wildcard bind")
	}
	if _, err := ListenSOCKS5("localhost:1080"); err == nil {
		t.Fatal("SOCKS5 listener unexpectedly accepted a hostname bind")
	}
}

func TestSOCKS5ConnectUsesDirectStream(t *testing.T) {
	left, _, accepted := newTestSessionPair(t, 8)
	broker := NewSessionBroker()
	broker.Set(left)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSOCKS5Listener(ctx, listener, broker) }()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		cancel()
		t.Fatalf("connect to SOCKS5 listener: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	if err := writeFull(client, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatal(err)
	}
	if methodReply != [2]byte{5, 0} {
		t.Fatalf("method reply = %v, want [5 0]", methodReply)
	}

	request := append([]byte{5, 1, 0, 3, 11}, []byte("example.com")...)
	request = append(request, 1, 187)
	if err := writeFull(client, request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT reply = %v", reply)
	}

	target := awaitTarget(t, accepted, "example.com:443")
	exchangeConns(t, client, target, "socks-request", "socks-response")

	cancel()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeSOCKS5Listener() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 listener did not stop after context cancellation")
	}
}

func TestReverseListenerUsesFixedMappingName(t *testing.T) {
	_, gatewaySession, accepted := newTestSessionPair(t, 8)
	broker := NewSessionBroker()
	broker.Set(gatewaySession)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeReverseListener(ctx, listener, "web", broker) }()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		cancel()
		t.Fatalf("connect to Reverse listener: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	target := awaitTarget(t, accepted, "web")
	exchangeConns(t, client, target, "reverse-request", "reverse-response")

	cancel()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeReverseListener() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reverse listener did not stop after context cancellation")
	}
}

func exchangeConns(t *testing.T, left, right net.Conn, request, response string) {
	t.Helper()
	_ = left.SetDeadline(time.Now().Add(2 * time.Second))
	_ = right.SetDeadline(time.Now().Add(2 * time.Second))

	writeDone := make(chan error, 1)
	go func() {
		_, err := left.Write([]byte(request))
		writeDone <- err
	}()
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(right, gotRequest); err != nil {
		t.Fatalf("target read request: %v", err)
	}
	if !bytes.Equal(gotRequest, []byte(request)) {
		t.Fatalf("target received %q, want %q", gotRequest, request)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}

	writeResponseDone := make(chan error, 1)
	go func() {
		_, err := right.Write([]byte(response))
		writeResponseDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(left, gotResponse); err != nil {
		t.Fatalf("client read response: %v", err)
	}
	if !bytes.Equal(gotResponse, []byte(response)) {
		t.Fatalf("client received %q, want %q", gotResponse, response)
	}
	if err := <-writeResponseDone; err != nil {
		t.Fatalf("target write response: %v", err)
	}
}


// Cancelled DNS work must fail promptly before attempting a Direct connection.
func TestDirectTargetHandlerHonorsCancelledDNSContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handler := NewDirectTargetHandler(map[uint16]struct{}{443: {}})
	conn, err := handler(ctx, TypeOpenDirect, []byte("example.invalid:443"))
	if conn != nil {
		_ = conn.Close()
		t.Fatal("cancelled Direct target lookup unexpectedly returned a connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Direct target error = %v, want context.Canceled", err)
	}
}

func TestReverseTargetHandlerReturnsDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetAddress := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	handler := NewReverseTargetHandler(map[string]string{"unavailable": targetAddress})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := handler(ctx, TypeOpenReverse, []byte("unavailable"))
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unavailable reverse target unexpectedly connected")
	}
	if err == nil {
		t.Fatal("unavailable reverse target unexpectedly succeeded")
	}
}
