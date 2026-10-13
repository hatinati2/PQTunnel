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
	"syscall"

	"github.com/hatinati2/PQTunnel/internal/tun"
	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

func main() {
	server := flag.String("server", "", "server IP:port (prefer literal IP to avoid pre-tunnel DNS)")
	serverName := flag.String("server-name", "", "TLS certificate DNS name or IP")
	caPath := flag.String("ca", "pki/ca.crt", "CA certificate PEM")
	certPath := flag.String("cert", "pki/client.crt", "client certificate PEM")
	keyPath := flag.String("key", "pki/client.key", "client private key PEM")
	tunName := flag.String("tun", "pqtun0", "TUN/Wintun adapter name")
	localIP := flag.String("local-ip", "10.66.0.2", "assigned client IPv4 address; must match client certificate CN")
	flag.Parse()
	if *server == "" || *serverName == "" {
		fatalIf(fmt.Errorf("--server and --server-name are required"))
	}
	ip, err := netip.ParseAddr(*localIP)
	fatalIf(err)
	if !ip.Is4() {
		fatalIf(fmt.Errorf("--local-ip must be IPv4"))
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
	fmt.Printf("PQTunnel client: %s; strict hybrid PQ key exchange; IPv4 only\n", *server)
	err = tunnel.RunClient(ctx, dev, tunnel.ClientConfig{ServerAddress: *server, ServerName: *serverName, LocalIP: ip, TLSConfig: tlsCfg})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, os.ErrClosed) {
		fatalIf(err)
	}
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-client:", err)
		os.Exit(1)
	}
}
