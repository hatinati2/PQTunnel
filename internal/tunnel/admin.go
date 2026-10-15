package tunnel

import (
	"sort"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

// AdminSnapshot returns only operational metadata needed by the loopback panel.
// It deliberately omits remote socket addresses, actual network prefixes,
// packet contents, certificate data and private-key paths.
func (s *Server) AdminSnapshot() adminapi.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := adminapi.Snapshot{
		Running:          s.running,
		ListenAddress:    s.ListenAddress,
		MaxClients:       s.MaxClients,
		SiteToSite:       len(s.PeerPrefixes) > 0 || len(s.LocalPrefixes) > 0,
		PeerIdentity:     s.PeerIdentity,
		PeerPrefixCount:  len(s.PeerPrefixes),
		LocalPrefixCount: len(s.LocalPrefixes),
	}
	if s.running && !s.startedAt.IsZero() {
		snapshot.Uptime = time.Since(s.startedAt).Truncate(time.Second).String()
	}
	for _, connected := range s.clients {
		duration := "نامشخص"
		if !connected.connectedAt.IsZero() {
			duration = time.Since(connected.connectedAt).Round(time.Second).String()
		}
		snapshot.Peers = append(snapshot.Peers, adminapi.Peer{
			Identity: connected.identity, ConnectedFor: duration,
		})
	}
	sort.Slice(snapshot.Peers, func(i, j int) bool {
		return snapshot.Peers[i].Identity < snapshot.Peers[j].Identity
	})
	return snapshot
}

// DisconnectPeer closes one authenticated peer connection without changing
// listeners, routing, firewall rules, certificates or any host networking state.
func (s *Server) DisconnectPeer(identity string) bool {
	if identity == "" {
		return false
	}
	s.mu.RLock()
	connected := s.clients[identity]
	s.mu.RUnlock()
	if connected == nil {
		return false
	}
	if connected.conn != nil {
		_ = connected.conn.Close()
	}
	return true
}
