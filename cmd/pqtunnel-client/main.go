package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/tun"
	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

func main() {
	server := flag.String("server", "", "remote endpoint host:port, IPv4:port, or [IPv6]:port")
	serverName := flag.String("server-name", "", "TLS certificate DNS name or IP SAN; required even when --server is an IP")
	network := flag.String("network", "tcp", "transport network: tcp (automatic IPv4/IPv6), tcp4, or tcp6")
	caPath := flag.String("ca", "pki/ca.crt", "CA certificate PEM")
	certPath := flag.String("cert", "pki/client.crt", "client/peer certificate PEM")
	keyPath := flag.String("key", "pki/client.key", "client/peer private key PEM")
	tunName := flag.String("tun", "pqtun0", "TUN/Wintun adapter name")
	localIP := flag.String("local-ip", "10.66.0.2", "legacy single-host IPv4 address; use prefix options for site-to-site mode")
	localPrefixesText := flag.String("local-prefixes", "", "comma-separated local source/destination CIDRs for site-to-site mode")
	remotePrefixesText := flag.String("remote-prefixes", "", "comma-separated allowed remote source/destination CIDRs; use 0.0.0.0/0 and/or ::/0 for default routes")
	allowedDstPortsText := flag.String("allowed-dst-ports", os.Getenv("PQTUNNEL_ALLOWED_DST_PORTS"), "optional outbound destination-port allowlist, e.g. tcp:443,udp:53,tcp:8000-8010")
	socketMark := flag.Uint("socket-mark", envUint("PQTUNNEL_SOCKET_MARK", 0), "optional Linux SO_MARK used to exempt tunnel transport from port-based policy routing")
	flag.Parse()
	if *server == "" || *serverName == "" {
		fatalIf(fmt.Errorf("--server and --server-name are required"))
	}
	if *network != "tcp" && *network != "tcp4" && *network != "tcp6" {
		fatalIf(fmt.Errorf("--network must be tcp, tcp4 or tcp6"))
	}
	localPrefixes, err := prefixset.ParseCSV(*localPrefixesText)
	fatalIf(err)
	remotePrefixes, err := prefixset.ParseCSV(*remotePrefixesText)
	fatalIf(err)
	allowedDstPorts, err := portpolicy.ParseCSV(*allowedDstPortsText)
	fatalIf(err)
	if (*localPrefixesText == "") != (*remotePrefixesText == "") {
		fatalIf(fmt.Errorf("site-to-site mode requires both --local-prefixes and --remote-prefixes; otherwise use legacy --local-ip mode"))
	}
	var ip netip.Addr
	if len(localPrefixes) == 0 {
		ip, err = netip.ParseAddr(*localIP)
		fatalIf(err)
		if !ip.Is4() {
			fatalIf(fmt.Errorf("legacy --local-ip must be IPv4; use --local-prefixes for IPv6"))
		}
	}
	caPEM, err := os.ReadFile(*caPath)
	fatalIf(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fatalIf(fmt.Errorf("invalid CA PEM"))
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	fatalIf(err)
	tlsCfg := tunnel.StrictTLS13Config()
	tlsCfg.RootCAs = roots
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.ServerName = *serverName
	dev, err := tun.Open(*tunName)
	fatalIf(err)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = dev.Close() }()
	fmt.Printf("PQTunnel dialer: %s via %s; TLS 1.3 strict hybrid X25519MLKEM768; IPv4/IPv6 packet support\n", *server, *network)
	err = tunnel.RunClient(ctx, dev, tunnel.ClientConfig{
		ServerAddress: *server, ServerName: *serverName, Network: *network,
		LocalIP: ip, LocalPrefixes: localPrefixes, RemotePrefixes: remotePrefixes, AllowedDstPorts: allowedDstPorts, SocketMark: uint32(*socketMark), TLSConfig: tlsCfg,
	})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, os.ErrClosed) {
		fatalIf(err)
	}
}

func envUint(name string, fallback uint) uint {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pqtunnel-client: invalid %s=%q\n", name, value)
		os.Exit(2)
	}
	return uint(parsed)
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-client:", err)
		os.Exit(1)
	}
}
