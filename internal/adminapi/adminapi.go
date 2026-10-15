package adminapi

// Peer is a deliberately small, privacy-preserving view of an authenticated
// tunnel peer. It excludes network addresses, packet data, certificates and keys.
type Peer struct {
	Identity     string
	ConnectedFor string
}

// Snapshot describes operational state safe to display in the local admin UI.
type Snapshot struct {
	Running          bool
	Uptime           string
	ListenAddress    string
	MaxClients       int
	SiteToSite       bool
	PeerIdentity     string
	PeerPrefixCount  int
	LocalPrefixCount int
	Peers            []Peer
}

// Controller is the narrow set of tunnel operations exposed to the admin UI.
type Controller interface {
	AdminSnapshot() Snapshot
	DisconnectPeer(identity string) bool
}
