package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminui"
	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/tun"
	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

func main() {
	listen := flag.String("listen", envString("PQTUNNEL_LISTEN", ":8443"), "TCP listen address; comma-separated addresses can bind IPv4 and IPv6, e.g. 0.0.0.0:8443,[::]:8443")
	adminListen := flag.String("admin-listen", envString("PQTUNNEL_ADMIN_LISTEN", ""), "optional local web admin address; only a literal loopback IP is allowed, disabled by default")
	tlsCert := flag.String("tls-cert", envString("PQTUNNEL_TLS_CERT", "/etc/pqtunnel/pki/server.crt"), "server certificate PEM")
	tlsKey := flag.String("tls-key", envString("PQTUNNEL_TLS_KEY", "/etc/pqtunnel/pki/server.key"), "server private key PEM")
	clientCA := flag.String("client-ca", envString("PQTUNNEL_CLIENT_CA", "/etc/pqtunnel/pki/ca.crt"), "CA that signed client certificates")
	tunName := flag.String("tun", "pqtun0", "Linux TUN interface name (systemd unit provisions pqtun0)")
	maxClients := flag.Int("max-clients", envInt("PQTUNNEL_MAX_CLIENTS", 128), "maximum simultaneous clients; set to 1 when using --peer-prefixes")
	peerPrefixesText := flag.String("peer-prefixes", os.Getenv("PQTUNNEL_PEER_PREFIXES"), "comma-separated allowed peer source/return-route CIDRs for a single site-to-site peer; supports IPv4 and IPv6")
	localPrefixesText := flag.String("local-prefixes", os.Getenv("PQTUNNEL_LOCAL_PREFIXES"), "comma-separated destination CIDRs allowed from the peer on this listener; required with --peer-prefixes")
	peerName := flag.String("peer-name", os.Getenv("PQTUNNEL_PEER_NAME"), "exact client certificate Common Name required in site-to-site mode")
	allowedDstPortsText := flag.String("allowed-dst-ports", os.Getenv("PQTUNNEL_ALLOWED_DST_PORTS"), "optional destination-port allowlist, e.g. tcp:443,udp:53,tcp:8000-8010; empty disables this filter")
	flag.Parse()

	adminToken := os.Getenv("PQTUNNEL_ADMIN_TOKEN")
	var adminListener net.Listener
	if *adminListen != "" {
		fatalIf(adminui.ValidateLoopbackAddress(*adminListen))
		if len([]byte(adminToken)) < 32 {
			fatalIf(fmt.Errorf("PQTUNNEL_ADMIN_TOKEN must contain at least 32 bytes when the admin panel is enabled"))
		}
		var listenErr error
		adminListener, listenErr = net.Listen("tcp", *adminListen)
		fatalIf(listenErr)
	}

	peerPrefixes, err := prefixset.ParseCSV(*peerPrefixesText)
	fatalIf(err)
	localPrefixes, err := prefixset.ParseCSV(*localPrefixesText)
	fatalIf(err)
	allowedDstPorts, err := portpolicy.ParseCSV(*allowedDstPortsText)
	fatalIf(err)
	siteToSite := len(peerPrefixes) > 0 || len(localPrefixes) > 0
	if siteToSite && (len(peerPrefixes) == 0 || len(localPrefixes) == 0) {
		fatalIf(fmt.Errorf("site-to-site mode requires both --peer-prefixes and --local-prefixes"))
	}
	if siteToSite && *maxClients != 1 {
		fatalIf(fmt.Errorf("site-to-site mode requires --max-clients=1"))
	}
	if siteToSite && *peerName == "" {
		fatalIf(fmt.Errorf("site-to-site mode requires --peer-name to pin the expected peer certificate identity"))
	}
	cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	fatalIf(err)
	caPEM, err := os.ReadFile(*clientCA)
	fatalIf(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fatalIf(fmt.Errorf("invalid client CA PEM"))
	}
	dev, err := tun.Open(*tunName)
	fatalIf(err)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &tunnel.Server{ListenAddress: *listen, TLSConfig: tunnel.ServerTLSConfig(cert, pool), Device: dev, MaxClients: *maxClients, PeerPrefixes: peerPrefixes, LocalPrefixes: localPrefixes, PeerIdentity: *peerName, AllowedDstPorts: allowedDstPorts}
	if adminListener != nil {
		adminHandler, err := adminui.New(adminToken, s)
		fatalIf(err)
		adminHTTP := &http.Server{
			Addr: *adminListen, Handler: adminHandler,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 8 << 10,
		}
		go func() {
			if err := adminHTTP.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, "pqtunneld: admin panel:", err)
				stop()
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = adminHTTP.Shutdown(shutdownCtx)
		}()
		fmt.Printf("PQTunnel admin panel available at http://%s/ (loopback-only; token protected)\\n", *adminListen)
	}
	fmt.Printf("PQTunnel listening on %s; TLS 1.3 strict X25519MLKEM768; IPv4/IPv6 packets; route policy configured separately\n", *listen)
	if err := s.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fatalIf(err)
	}
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		fmt.Fprintf(os.Stderr, "pqtunneld: invalid %s=%q\n", name, value)
		os.Exit(2)
	}
	return parsed
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunneld:", err)
		os.Exit(1)
	}
}
