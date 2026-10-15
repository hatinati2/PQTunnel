package main

import (
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

// clientAdminController exposes the dialer's current authenticated transport
// through the same private control socket used by the gateway. It never
// changes routes or host networking state.
type clientAdminController struct {
	mu sync.RWMutex

	serverAddress string
	serverName    string
	localPrefixes []netip.Prefix
	remotePrefixes []netip.Prefix
	startedAt     time.Time

	conn        net.Conn
	identity    string
	connectedAt time.Time
}

func newClientAdminController(serverAddress, serverName string, local, remote []netip.Prefix) *clientAdminController {
	return &clientAdminController{
		serverAddress: serverAddress,
		serverName: serverName,
		localPrefixes: append([]netip.Prefix(nil), local...),
		remotePrefixes: append([]netip.Prefix(nil), remote...),
		startedAt: time.Now(),
	}
}

func (c *clientAdminController) OnConnected(conn net.Conn) {
	identity := c.serverName
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 && state.PeerCertificates[0].Subject.CommonName != "" {
			identity = state.PeerCertificates[0].Subject.CommonName
		}
	}
	c.mu.Lock()
	c.conn = conn
	c.identity = identity
	c.connectedAt = time.Now()
	c.mu.Unlock()
}

func (c *clientAdminController) OnDisconnected(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Ignore an old connection callback if a future implementation ever
	// reports lifecycle events asynchronously and a newer connection exists.
	if c.conn != conn {
		return
	}
	c.conn = nil
	c.identity = ""
	c.connectedAt = time.Time{}
}

func (c *clientAdminController) AdminSnapshot() adminapi.Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snapshot := adminapi.Snapshot{
		Running: true,
		TransportConnected: c.conn != nil,
		ListenAddress: c.serverAddress,
		MaxClients: 1,
		SiteToSite: len(c.localPrefixes) > 0 && len(c.remotePrefixes) > 0,
		PeerIdentity: c.serverName,
		PeerPrefixCount: len(c.remotePrefixes),
		LocalPrefixCount: len(c.localPrefixes),
	}
	if !c.startedAt.IsZero() {
		snapshot.Uptime = time.Since(c.startedAt).Truncate(time.Second).String()
	}
	if c.conn != nil {
		if c.identity != "" {
			snapshot.PeerIdentity = c.identity
		}
		connectedFor := "نامشخص"
		if !c.connectedAt.IsZero() {
			connectedFor = time.Since(c.connectedAt).Round(time.Second).String()
		}
		snapshot.Peers = []adminapi.Peer{{Identity: c.identity, ConnectedFor: connectedFor}}
	}
	return snapshot
}

// DisconnectPeer ends only the current TLS transport. The dialer's existing
// reconnect loop remains active, so this is not a persistent peer ban.
func (c *clientAdminController) DisconnectPeer(identity string) bool {
	c.mu.RLock()
	conn := c.conn
	currentIdentity := c.identity
	c.mu.RUnlock()
	if conn == nil || identity == "" || identity != currentIdentity {
		return false
	}
	return conn.Close() == nil
}
