package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/proxymux"
	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

const (
	defaultDialTimeout = 10 * time.Second
	minRetryDelay      = time.Second
	maxRetryDelay      = 20 * time.Second
	maxTLSHandshakes   = 8
)

type config struct {
	Role              string
	Listen            string
	Server            string
	ServerName        string
	CAPath            string
	CertPath          string
	KeyPath           string
	PeerName          string
	DirectListen      string
	DirectAllowedPort string
	ReverseListeners  string
	ReverseTargets    string
	MaxStreams        int
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.Role, "role", env("PQTUNNEL_PROXY_ROLE", ""), "role: gateway or dialer")
	flag.StringVar(&cfg.Listen, "listen", env("PQTUNNEL_PROXY_LISTEN", ""), "Gateway TLS listener address (explicit host:port)")
	flag.StringVar(&cfg.Server, "server", env("PQTUNNEL_PROXY_SERVER", ""), "Gateway host:port for the Dialer")
	flag.StringVar(&cfg.ServerName, "server-name", env("PQTUNNEL_PROXY_SERVER_NAME", ""), "Gateway certificate DNS name or IP SAN")
	flag.StringVar(&cfg.CAPath, "ca", env("PQTUNNEL_PROXY_CA", "/etc/pqtunnel/pki/ca.crt"), "CA certificate PEM")
	flag.StringVar(&cfg.CertPath, "cert", env("PQTUNNEL_PROXY_CERT", ""), "role-specific certificate PEM")
	flag.StringVar(&cfg.KeyPath, "key", env("PQTUNNEL_PROXY_KEY", ""), "role-specific private key PEM")
	flag.StringVar(&cfg.PeerName, "peer-name", env("PQTUNNEL_PROXY_PEER_NAME", ""), "exact client certificate Common Name (Gateway only)")
	flag.StringVar(&cfg.DirectListen, "direct-listen", env("PQTUNNEL_PROXY_DIRECT_LISTEN", "127.0.0.1:1080"), "loopback SOCKS5 listener (Dialer only; empty disables Direct)")
	flag.StringVar(&cfg.DirectAllowedPort, "direct-allowed-ports", env("PQTUNNEL_PROXY_DIRECT_ALLOWED_PORTS", ""), "required Gateway TCP destination allowlist, e.g. 80,443")
	flag.StringVar(&cfg.ReverseListeners, "reverse-listeners", env("PQTUNNEL_PROXY_REVERSE_LISTENERS", ""), "Gateway listeners, name=host:port,name2=host:port")
	flag.StringVar(&cfg.ReverseTargets, "reverse-targets", env("PQTUNNEL_PROXY_REVERSE_TARGETS", ""), "Dialer targets, name=host:port,name2=host:port")
	maxStreamsText := env("PQTUNNEL_PROXY_MAX_STREAMS", "128")
	flag.StringVar(&maxStreamsText, "max-streams", maxStreamsText, "max logical streams per authenticated transport (1-512)")
	flag.Parse()
	maxStreams, err := strconv.Atoi(maxStreamsText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-proxy: --max-streams must be a decimal integer")
		os.Exit(2)
	}
	cfg.MaxStreams = maxStreams

	if err := run(cfg); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "pqtunnel-proxy:", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func run(cfg config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Role != "gateway" && cfg.Role != "dialer" {
		return errors.New("set --role gateway or --role dialer")
	}
	if cfg.MaxStreams < 1 || cfg.MaxStreams > 512 {
		return errors.New("--max-streams must be between 1 and 512")
	}
	caPool, err := loadCAPool(cfg.CAPath)
	if err != nil {
		return err
	}
	cert, err := loadRoleCertificate(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return err
	}
	if cfg.Role == "gateway" {
		return runGateway(ctx, cfg, cert, caPool)
	}
	return runDialer(ctx, cfg, cert, caPool)
}


func loadRoleCertificate(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, errors.New("--cert and --key are required")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stat private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return tls.Certificate{}, errors.New("private key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return tls.Certificate{}, errors.New("private key permissions are too broad; use mode 0600")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load role certificate and key: %w", err)
	}
	return cert, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("CA certificate path is required")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file does not contain a valid PEM certificate")
	}
	return pool, nil
}

func runGateway(ctx context.Context, cfg config, cert tls.Certificate, caPool *x509.CertPool) error {
	if cfg.Listen == "" || cfg.PeerName == "" {
		return errors.New("Gateway requires --listen and --peer-name")
	}
	allowedPorts, err := proxymux.ParseTCPPortSet(cfg.DirectAllowedPort)
	if err != nil {
		return fmt.Errorf("Gateway Direct allowlist: %w", err)
	}
	reverseListeners, err := proxymux.ParseNamedAddresses(cfg.ReverseListeners)
	if err != nil {
		return fmt.Errorf("Gateway Reverse listeners: %w", err)
	}
	if len(reverseListeners) == 0 {
		return errors.New("Gateway requires at least one explicit Reverse listener mapping")
	}

	broker := proxymux.NewSessionBroker()
	opened := make([]net.Listener, 0, len(reverseListeners))
	for name, address := range reverseListeners {
		listener, err := proxymux.ListenReverse(address)
		if err != nil {
			for _, openedListener := range opened {
				_ = openedListener.Close()
			}
			return fmt.Errorf("bind Reverse listener %q: %w", name, err)
		}
		opened = append(opened, listener)
		go func(mapping string, ln net.Listener) {
			if serveErr := proxymux.ServeReverseListener(ctx, ln, mapping, broker); serveErr != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "pqtunnel-proxy: Reverse listener %q: %v\n", mapping, serveErr)
			}
		}(name, listener)
	}
	defer func() {
		for _, listener := range opened {
			_ = listener.Close()
		}
	}()

	rawListener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("bind Gateway transport listener: %w", err)
	}
	serverTLS := tunnel.ServerTLSConfig(cert, caPool)
	listener := tls.NewListener(rawListener, serverTLS)
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopListener()

	fmt.Fprintf(os.Stderr, "pqtunnel-proxy: Gateway listening at %s; existing firewall policy is not modified\n", cfg.Listen)
	slots := make(chan struct{}, maxTLSHandshakes)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept Gateway transport: %w", err)
		}
		select {
		case slots <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-slots }()
				serveGatewaySession(ctx, c, cfg, allowedPorts, broker)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func serveGatewaySession(ctx context.Context, conn net.Conn, cfg config, allowedPorts map[uint16]struct{}, broker *proxymux.SessionBroker) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout)
	err := tc.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		_ = tc.Close()
		return
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != cfg.PeerName {
		_ = tc.Close()
		return
	}

	session, err := proxymux.NewSession(ctx, tc, proxymux.SessionOptions{
		Initiator: false, MaxStreams: cfg.MaxStreams,
		OnOpen: proxymux.NewDirectTargetHandler(allowedPorts),
	})
	if err != nil {
		_ = tc.Close()
		return
	}
	broker.Set(session)
	select {
	case <-ctx.Done():
	case <-session.Done():
	}
	broker.Clear(session)
	_ = session.Close()
}

func runDialer(ctx context.Context, cfg config, cert tls.Certificate, caPool *x509.CertPool) error {
	if cfg.Server == "" || cfg.ServerName == "" {
		return errors.New("Dialer requires --server and --server-name")
	}
	if cfg.DirectListen == "" {
		return errors.New("Dialer requires an explicit loopback Direct SOCKS5 listener")
	}
	reverseTargets, err := proxymux.ParseNamedAddresses(cfg.ReverseTargets)
	if err != nil {
		return fmt.Errorf("Dialer Reverse targets: %w", err)
	}
	if len(reverseTargets) == 0 {
		return errors.New("Dialer requires at least one fixed Reverse target mapping")
	}

	broker := proxymux.NewSessionBroker()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if cfg.DirectListen != "" {
		listener, err := proxymux.ListenSOCKS5(cfg.DirectListen)
		if err != nil {
			return fmt.Errorf("bind loopback SOCKS5 listener: %w", err)
		}
		go func() {
			if serveErr := proxymux.ServeSOCKS5Listener(runCtx, listener, broker); serveErr != nil && runCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "pqtunnel-proxy: SOCKS5 listener: %v\n", serveErr)
				cancel()
			}
		}()
		fmt.Fprintf(os.Stderr, "pqtunnel-proxy: Direct SOCKS5 proxy listening at %s\n", listener.Addr())
	}

	tlsConfig := tunnel.StrictTLS13Config()
	tlsConfig.RootCAs = caPool
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.ServerName = cfg.ServerName

	backoff := minRetryDelay
	for runCtx.Err() == nil {
		dialCtx, dialCancel := context.WithTimeout(runCtx, defaultDialTimeout)
		dialer := net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}
		rawConn, err := dialer.DialContext(dialCtx, "tcp", cfg.Server)
		if err == nil {
			tc := tls.Client(rawConn, tlsConfig.Clone())
			err = tc.HandshakeContext(dialCtx)
			if err != nil {
				_ = tc.Close()
			} else {
				session, sessionErr := proxymux.NewSession(runCtx, tc, proxymux.SessionOptions{
					Initiator: true, MaxStreams: cfg.MaxStreams,
					OnOpen: proxymux.NewReverseTargetHandler(reverseTargets),
				})
				if sessionErr == nil {
					broker.Set(session)
					fmt.Fprintf(os.Stderr, "pqtunnel-proxy: authenticated transport connected to %s\n", cfg.Server)
					select {
					case <-runCtx.Done():
					case <-session.Done():
					}
					broker.Clear(session)
					_ = session.Close()
				} else {
					_ = tc.Close()
					err = sessionErr
				}
			}
		}
		dialCancel()
		if runCtx.Err() != nil {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "pqtunnel-proxy: transport disconnected or unavailable: %v\n", err)
		}
		if !sleepContext(runCtx, backoff) {
			break
		}
		backoff = min(backoff*2, maxRetryDelay)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return runCtx.Err()
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
