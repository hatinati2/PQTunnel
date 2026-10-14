package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/packet"
	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

const maxQueuedPackets = 512

type SocketProtector func(fd uintptr) error

type ClientConfig struct {
	ServerAddress   string
	ServerName      string
	Network         string             // tcp (auto), tcp4, or tcp6
	LocalIP         netip.Addr         // legacy single-host mode; ignored when LocalPrefixes is set
	LocalPrefixes   []netip.Prefix     // allowed local source/destination ranges for site-to-site links
	RemotePrefixes  []netip.Prefix     // permitted remote source/destination ranges; empty means unrestricted
	AllowedDstPorts portpolicy.RuleSet // optional filter for outbound packets read from TUN
	SocketMark      uint32             // optional Linux SO_MARK to exempt the tunnel transport from policy routing
	TLSConfig       *tls.Config
	ProtectSocket   SocketProtector
}

// RunClient carries IPv4 and IPv6 layer-3 packets over a TLS connection.
// When prefixes are configured, it enforces source/destination policy for a
// server-to-server routed link. With legacy LocalIP only, it remains host mode.
func RunClient(ctx context.Context, dev io.ReadWriteCloser, cfg ClientConfig) error {
	if cfg.ServerAddress == "" || cfg.TLSConfig == nil || cfg.TLSConfig.ServerName == "" {
		return fmt.Errorf("server address, server name and TLS config are required")
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Network != "tcp" && cfg.Network != "tcp4" && cfg.Network != "tcp6" {
		return fmt.Errorf("network must be tcp, tcp4 or tcp6")
	}
	// RunClient owns the device lifetime while running. Closing it on cancellation
	// unblocks the dedicated TUN reader goroutine if Read is waiting for a packet.
	stopDeviceClose := context.AfterFunc(ctx, func() { _ = dev.Close() })
	defer stopDeviceClose()

	localPrefixes := cfg.LocalPrefixes
	if len(localPrefixes) == 0 {
		if !cfg.LocalIP.IsValid() {
			return fmt.Errorf("local IP or local prefixes are required")
		}
		bits := 128
		if cfg.LocalIP.Is4() {
			bits = 32
		}
		localPrefixes = []netip.Prefix{netip.PrefixFrom(cfg.LocalIP, bits)}
	}
	out := make(chan []byte, maxQueuedPackets)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, protocol.MaxFrameSize)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				select {
				case readErr <- err:
				default:
				}
				return
			}
			if n <= 0 {
				continue
			}
			src, dst, p, err := packet.IP(buf[:n])
			if err != nil || !prefixset.Contains(localPrefixes, src) {
				continue
			}
			if len(cfg.RemotePrefixes) > 0 && !prefixset.Contains(cfg.RemotePrefixes, dst) {
				continue
			}
			if !cfg.AllowedDstPorts.AllowsPacket(p) {
				continue
			}
			copyPacket := append([]byte(nil), p...)
			select {
			case out <- copyPacket:
			default: // bounded queue: drop under congestion
			}
		}
	}()

	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return fmt.Errorf("TUN read: %w", err)
		default:
		}
		conn, err := dialTLS(ctx, cfg)
		if err != nil {
			if !sleepContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = min(backoff*2, 20*time.Second)
			continue
		}
		backoff = time.Second
		sessionCtx, cancel := context.WithCancel(ctx)
		stopConnClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
		writeErr := make(chan error, 1)
		go func() { writeErr <- writePackets(sessionCtx, conn, out) }()
		go func() {
			select {
			case <-sessionCtx.Done():
			case werr := <-writeErr:
				if werr != nil {
					_ = conn.Close()
				}
			}
		}()
		readSessionErr := readPackets(sessionCtx, conn, dev, localPrefixes, cfg.RemotePrefixes)
		stopConnClose()
		cancel()
		_ = conn.Close()
		drain(out)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return fmt.Errorf("TUN read: %w", err)
		default:
		}
		if readSessionErr != nil && !errors.Is(readSessionErr, net.ErrClosed) && !errors.Is(readSessionErr, io.EOF) {
			// Transport/protocol errors trigger reconnect; no classical TLS fallback.
			_ = readSessionErr
		}
		if !sleepContext(ctx, backoff) {
			return ctx.Err()
		}
		backoff = min(backoff*2, 20*time.Second)
	}
}

func dialTLS(ctx context.Context, cfg ClientConfig) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if cfg.ProtectSocket != nil || cfg.SocketMark != 0 {
		d.Control = func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				if cfg.SocketMark != 0 {
					controlErr = setSocketMark(fd, cfg.SocketMark)
					if controlErr != nil {
						return
					}
				}
				if cfg.ProtectSocket != nil {
					controlErr = cfg.ProtectSocket(fd)
				}
			}); err != nil {
				return err
			}
			return controlErr
		}
	}
	raw, err := d.DialContext(ctx, cfg.Network, cfg.ServerAddress)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg.TLSConfig.Clone())
	handshakeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

func writePackets(ctx context.Context, conn net.Conn, packets <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p := <-packets:
			if err := protocol.WriteFrame(conn, p); err != nil {
				return err
			}
		}
	}
}

func readPackets(ctx context.Context, conn net.Conn, dev io.Writer, localPrefixes, remotePrefixes []netip.Prefix) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}
		src, dst, normalized, err := packet.IP(p)
		if err != nil || !prefixset.Contains(localPrefixes, dst) {
			continue
		}
		if len(remotePrefixes) > 0 && !prefixset.Contains(remotePrefixes, src) {
			continue
		}
		n, err := dev.Write(normalized)
		if err != nil {
			return err
		}
		if n != len(normalized) {
			return io.ErrShortWrite
		}
	}
}

func drain(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
