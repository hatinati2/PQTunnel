package adminapi

import "context"

// Peer is a deliberately small, privacy-preserving view of an authenticated
// tunnel peer. It excludes network addresses, packet data, certificates and keys.
type Peer struct {
	Identity     string
	ConnectedFor string
}

// Snapshot describes operational state safe to display in the local admin UI.
type Snapshot struct {
	Running             bool
	TransportConnected  bool
	Uptime              string
	ListenAddress    string
	MaxClients       int
	SiteToSite       bool
	PeerIdentity     string
	PeerPrefixCount  int
	LocalPrefixCount int
	Peers            []Peer
}

// Controller is the narrow set of tunnel operations exposed to the in-process
// admin UI. The standalone manager can implement it through local IPC.
type Controller interface {
	AdminSnapshot() Snapshot
	DisconnectPeer(identity string) bool
}

// TunnelConfiguration contains only non-secret, explicitly editable server-to-server
// settings. Certificate paths, keys, admin tokens, service names and arbitrary
// environment variables are intentionally not exposed here.
type TunnelConfiguration struct {
	ListenAddress   string
	MaxClients      int
	PeerPrefixes    string
	LocalPrefixes   string
	PeerIdentity    string
	ServerAddress   string
	ServerName      string
	RemotePrefixes  string
	AllowedDstPorts string
}

// ManagerSnapshot contains local service-management metadata safe for the web UI.
// It must never include private keys, CA material, admin tokens, raw environment
// files, socket addresses of peers, or arbitrary systemd properties.
type SpeedTestResult struct {
	Peer            string
	SizeMiB         int
	RTTMillis       float64
	UploadMbps      float64
	DownloadMbps    float64
	UploadSeconds   float64
	DownloadSeconds float64
	CompletedAt     string
}

type ManagerSnapshot struct {
	Role                string
	ServiceUnit         string
	ActiveState         string
	SubState             string
	MainPID              string
	Config               TunnelConfiguration
	ConfigReady          bool
	ConfigError          string
	PeerDataReady        bool
	TransportConnected   bool
	Uptime               string
	Peers                []Peer
	SpeedTestPeer        string
	SpeedTestReady bool
	LastSpeedTest *SpeedTestResult
}

// ManagerController is implemented only by the standalone, explicitly installed
// manager service. Existing in-process panels do not gain systemd/config authority.
type ManagerController interface {
	ManagementSnapshot() ManagerSnapshot
	ServiceAction(ctx context.Context, action string) error
	ApplyConfiguration(ctx context.Context, config TunnelConfiguration) error
	RunSpeedTest(ctx context.Context, sizeMiB int) (SpeedTestResult, error)
	RecentLogs(ctx context.Context) (string, error)
}

 // SiteToSiteSetupRequest is a constrained, validated request for the guided
 // two-VPS setup. It intentionally contains no private keys, passwords, shell
 // fragments, or arbitrary command-line arguments.
 type SiteToSiteSetupRequest struct {
  GatewaySSHTarget string
  SSHPort int
  GatewayName string
  TLSPort int
  TCPPorts string
  UDPPorts string
  DialerWAN string
  GatewayWAN string
  Confirm string
 }

 // SiteToSiteSetupStatus exposes only redacted logs and state for the fixed
 // site-to-site setup worker. Tokens can be consumed separately exactly once.
 type SiteToSiteSetupStatus struct {
  Available bool
  State string
  Running bool
  Success bool
  TokensAvailable bool
  Output string
 }

 type SiteToSiteSetupTokens struct {
  Dialer string
  Gateway string
  SpeedTest string
 }

 type SetupWizardController interface {
  StartSiteToSiteSetup(ctx context.Context, request SiteToSiteSetupRequest) error
  SiteToSiteSetupStatus(ctx context.Context) (SiteToSiteSetupStatus, error)
  ConsumeSiteToSiteSetupTokens(ctx context.Context) (SiteToSiteSetupTokens, error)
  ApproveSiteToSiteSetup(ctx context.Context) error
 }


// NodeSetupRequest selects one fixed local-endpoint operation. It contains only
// public endpoint metadata; private keys are always generated and retained locally.
type NodeSetupRequest struct {
	Operation string
	PublicName string
	ListenPort int
	TCPPorts string
	UDPPorts string
}

// NodeSetupStatus is a bounded status view for the independent, per-host pairing flow.
type NodeSetupStatus struct {
	Available bool
	Role string
	State string
	Output string
	BundleAvailable bool
}

// NodeSetupController exposes only fixed, validated operations and public-CA bundle transfer.
type NodeSetupController interface {
	StartNodeSetup(ctx context.Context, request NodeSetupRequest) error
	NodeSetupStatus(ctx context.Context) (NodeSetupStatus, error)
	UploadNodeSetupBundle(ctx context.Context, data []byte) error
	ReadNodeSetupBundle(ctx context.Context) ([]byte, error)
}
