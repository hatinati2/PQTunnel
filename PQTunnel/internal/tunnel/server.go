package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel/internal/packet"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

// Server routes IPv4 packets between authenticated client sessions and a single server TUN.
// The host's IP forwarding, default route, and NAT are deliberately managed outside this code.
type Server struct {
	ListenAddress string
	TLSConfig     *tls.Config
	Device        io.ReadWriteCloser
	MaxClients    int

	mu      sync.RWMutex
	clients map[netip.Addr]*peer
}

type peer struct {
	ip      netip.Addr
	conn    net.Conn
	writeMu sync.Mutex
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Device == nil || s.TLSConfig == nil || s.ListenAddress == "" {
		return fmt.Errorf("device, TLS config and listen address are required")
	}
	if s.MaxClients <= 0 {
		s.MaxClients = 128
	}
	s.clients = make(map[netip.Addr]*peer)
	ln, err := tls.Listen("tcp", s.ListenAddress, s.TLSConfig.Clone())
	if err != nil {
		return err
	}
	defer ln.Close()
	// Bound both authenticated sessions and in-progress TLS handshakes. Without
	// this semaphore, a peer could create unbounded handshake goroutines before
	// the post-authentication client limit is checked.
	slots := make(chan struct{}, s.MaxClients)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = s.Device.Close()
		s.mu.RLock()
		for _, p := range s.clients {
			_ = p.conn.Close()
		}
		s.mu.RUnlock()
	}()
	go s.routePackets(ctx)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			continue
		}
		select {
		case slots <- struct{}{}:
			go func(conn net.Conn) {
				defer func() { <-slots }()
				s.handle(ctx, conn)
			}(c)
		default:
			_ = c.Close()
		}
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return
	}
	hctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		_ = c.Close()
		return
	}
	stopConnClose := context.AfterFunc(ctx, func() { _ = tc.Close() })
	defer stopConnClose()
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = c.Close()
		return
	}
	ip, err := netip.ParseAddr(state.PeerCertificates[0].Subject.CommonName)
	if err != nil || !ip.Is4() {
		_ = c.Close()
		return
	}
	p := &peer{ip: ip, conn: tc}
	s.mu.Lock()
	if len(s.clients) >= s.MaxClients {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	if _, exists := s.clients[ip]; exists {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	s.clients[ip] = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.clients[ip] == p {
			delete(s.clients, ip)
		}
		s.mu.Unlock()
		_ = c.Close()
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		packetBytes, err := protocol.ReadFrame(tc)
		if err != nil {
			return
		}
		src, _, pkt, err := packet.IPv4(packetBytes)
		if err != nil {
			continue
		} // silently drop IPv6 and malformed packets
		if src != ip {
			return
		} // client source-address spoofing: terminate session
		n, writeErr := s.Device.Write(pkt)
		if writeErr != nil || n != len(pkt) {
			return
		}
	}
}

func (s *Server) routePackets(ctx context.Context) {
	buf := make([]byte, protocol.MaxFrameSize)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := s.Device.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		_, dst, pkt, err := packet.IPv4(buf[:n])
		if err != nil {
			continue
		}
		s.mu.RLock()
		p := s.clients[dst]
		s.mu.RUnlock()
		if p == nil {
			continue
		}
		p.writeMu.Lock()
		_ = p.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		err = protocol.WriteFrame(p.conn, pkt)
		_ = p.conn.SetWriteDeadline(time.Time{})
		p.writeMu.Unlock()
		if err != nil {
			_ = p.conn.Close()
		}
	}
}

func ServerTLSConfig(cert tls.Certificate, clientCA *x509.CertPool) *tls.Config {
	cfg := StrictTLS13Config()
	cfg.Certificates = []tls.Certificate{cert}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = clientCA
	cfg.SessionTicketsDisabled = true
	return cfg
}
