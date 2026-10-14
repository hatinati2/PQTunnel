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
	"strings"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel/internal/packet"
	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

// Server routes IPv4/IPv6 packets between authenticated peers and a single
// server TUN. Host forwarding, routes and NAT are managed separately.
type Server struct {
	ListenAddress string
	TLSConfig     *tls.Config
	Device        io.ReadWriteCloser
	MaxClients    int
	// PeerPrefixes is the remote peer's source allowlist and return-route set.
	// LocalPrefixes is the listener side's destination allowlist for packets
	// received from that peer. Configure both in site-to-site mode.
	PeerPrefixes    []netip.Prefix
	LocalPrefixes   []netip.Prefix
	PeerIdentity    string             // exact certificate Common Name required in single-peer site-to-site mode
	AllowedDstPorts portpolicy.RuleSet // optional defense-in-depth TCP/UDP destination-port allowlist

	mu      sync.RWMutex
	clients map[string]*peer
}

type peer struct {
	identity string
	prefixes []netip.Prefix
	conn     net.Conn
	writeMu  sync.Mutex
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Device == nil || s.TLSConfig == nil || s.ListenAddress == "" {
		return fmt.Errorf("device, TLS config and listen address are required")
	}
	if s.MaxClients <= 0 {
		s.MaxClients = 128
	}
	siteToSite := len(s.PeerPrefixes) > 0 || len(s.LocalPrefixes) > 0
	if siteToSite && (len(s.PeerPrefixes) == 0 || len(s.LocalPrefixes) == 0) {
		return fmt.Errorf("site-to-site mode requires both peer source/route prefixes and local destination prefixes")
	}
	if siteToSite && s.MaxClients != 1 {
		return fmt.Errorf("site-to-site mode requires max-clients=1; prefixes are assigned to one authenticated peer")
	}
	if siteToSite && s.PeerIdentity == "" {
		return fmt.Errorf("site-to-site mode requires an expected peer identity")
	}
	if siteToSite {
		if err := validateDisjointPrefixes(s.PeerPrefixes, s.LocalPrefixes, false); err != nil {
			return fmt.Errorf("site-to-site peer and local prefixes: %w", err)
		}
	}
	for _, pfx := range append(append([]netip.Prefix(nil), s.PeerPrefixes...), s.LocalPrefixes...) {
		if !pfx.IsValid() || pfx != pfx.Masked() {
			return fmt.Errorf("site-to-site prefixes must be valid masked CIDR networks")
		}
	}
	s.clients = make(map[string]*peer)

	addresses := strings.Split(s.ListenAddress, ",")
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("empty listen address in comma-separated --listen list")
		}
		network := "tcp"
		if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
			if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
				if ip.Is4() {
					network = "tcp4"
				} else {
					network = "tcp6"
				}
			}
		}
		ln, err := tls.Listen(network, address, s.TLSConfig.Clone())
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("listen on %s: %w", address, err)
		}
		listeners = append(listeners, ln)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	// A child context lets Serve tear down all background work even when it
	// returns because an accept loop fails rather than because the caller cancels.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	slots := make(chan struct{}, s.MaxClients)
	go func() {
		<-runCtx.Done()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		_ = s.Device.Close()
		s.mu.RLock()
		for _, p := range s.clients {
			_ = p.conn.Close()
		}
		s.mu.RUnlock()
	}()
	go s.routePackets(runCtx)
	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(listener net.Listener) { errCh <- s.acceptLoop(runCtx, listener, slots) }(ln)
	}
	select {
	case <-runCtx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, slots chan struct{}) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept on %s: %w", ln.Addr(), err)
		}
		select {
		case slots <- struct{}{}:
			go func(conn net.Conn) { defer func() { <-slots }(); s.handle(ctx, conn) }(c)
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
	identity := state.PeerCertificates[0].Subject.CommonName
	if identity == "" || (s.PeerIdentity != "" && identity != s.PeerIdentity) {
		_ = c.Close()
		return
	}

	prefixes := append([]netip.Prefix(nil), s.PeerPrefixes...)
	if len(prefixes) == 0 {
		// Backward compatibility: legacy client certificates use an IP address
		// as Common Name. This becomes a host-only allowlist.
		ip, parseErr := netip.ParseAddr(identity)
		if parseErr != nil {
			_ = c.Close()
			return
		}
		prefixes = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
	}
	for _, pfx := range prefixes {
		if !pfx.IsValid() {
			_ = c.Close()
			return
		}
	}
	p := &peer{identity: identity, prefixes: prefixes, conn: tc}
	s.mu.Lock()
	if len(s.clients) >= s.MaxClients {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	if _, exists := s.clients[identity]; exists {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	for _, existing := range s.clients {
		if prefixset.Overlap(existing.prefixes, prefixes) {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
	}
	s.clients[identity] = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.clients[identity] == p {
			delete(s.clients, identity)
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
		src, dst, pkt, err := packet.IP(packetBytes)
		if err != nil {
			tracePacketFlow("server peer->tun drop=malformed bytes=%d err=%v", len(packetBytes), err)
			continue
		}
		tracePacketFlow("server peer->tun received peer=%s src=%s dst=%s bytes=%d", identity, src, dst, len(pkt))
		if !peerPacketAllowed(src, dst, p.prefixes, s.LocalPrefixes) {
			if !prefixset.Contains(p.prefixes, src) {
				tracePacketFlow("server peer->tun drop=unauthorized-source peer=%s src=%s dst=%s", identity, src, dst)
				return // spoofed source: terminate session
			}
			tracePacketFlow("server peer->tun drop=destination-outside-local-prefixes peer=%s src=%s dst=%s", identity, src, dst)
			continue // destination is outside this listener's configured prefixes
		}
		if !s.AllowedDstPorts.AllowsPacket(pkt) {
			tracePacketFlow("server peer->tun drop=destination-port-policy peer=%s src=%s dst=%s", identity, src, dst)
			continue // destination protocol/port is not in the configured allowlist
		}
		n, writeErr := s.Device.Write(pkt)
		tracePacketFlow("server peer->tun injected peer=%s src=%s dst=%s bytes=%d written=%d err=%v", identity, src, dst, len(pkt), n, writeErr)
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
		src, dst, pkt, err := packet.IP(buf[:n])
		if err != nil {
			tracePacketFlow("server tun->peer drop=malformed bytes=%d err=%v", n, err)
			continue
		}
		s.mu.RLock()
		target := peerForDestination(s.clients, dst)
		s.mu.RUnlock()
		if target == nil {
			tracePacketFlow("server tun->peer drop=no-unique-peer-route src=%s dst=%s bytes=%d", src, dst, len(pkt))
			continue // no route or ambiguous route
		}
		target.writeMu.Lock()
		_ = target.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		err = protocol.WriteFrame(target.conn, pkt)
		_ = target.conn.SetWriteDeadline(time.Time{})
		target.writeMu.Unlock()
		if err != nil {
			tracePacketFlow("server tun->peer write-failed peer=%s src=%s dst=%s bytes=%d err=%v", target.identity, src, dst, len(pkt), err)
			_ = target.conn.Close()
			continue
		}
		tracePacketFlow("server tun->peer forwarded peer=%s src=%s dst=%s bytes=%d", target.identity, src, dst, len(pkt))
	}
}

// peerForDestination returns a peer only when exactly one peer route matches.
// Ambiguous or unmatched destinations are dropped instead of being guessed.
func peerForDestination(peers map[string]*peer, dst netip.Addr) *peer {
	var target *peer
	matches := 0
	for _, p := range peers {
		if prefixset.Contains(p.prefixes, dst) {
			target = p
			matches++
		}
	}
	if matches != 1 {
		return nil
	}
	return target
}

func ServerTLSConfig(cert tls.Certificate, clientCA *x509.CertPool) *tls.Config {
	cfg := StrictTLS13Config()
	cfg.Certificates = []tls.Certificate{cert}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = clientCA
	cfg.SessionTicketsDisabled = true
	return cfg
}

// peerPacketAllowed enforces the authenticated peer's source ranges and the
// listener-side destination ranges. An empty destination allowlist preserves
// legacy host mode; site-to-site configuration validation requires it to be set.
func peerPacketAllowed(src, dst netip.Addr, peerPrefixes, localPrefixes []netip.Prefix) bool {
	if !prefixset.Contains(peerPrefixes, src) {
		return false
	}
	return len(localPrefixes) == 0 || prefixset.Contains(localPrefixes, dst)
}
