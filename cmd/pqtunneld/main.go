package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hatinati2/PQTunnel/internal/tun"
	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

func main() {
	listen := flag.String("listen", ":8443", "TCP listen address")
	tlsCert := flag.String("tls-cert", "pki/server.crt", "server certificate PEM")
	tlsKey := flag.String("tls-key", "pki/server.key", "server private key PEM")
	clientCA := flag.String("client-ca", "pki/ca.crt", "CA that signed client certificates")
	tunName := flag.String("tun", "pqtun0", "Linux TUN interface name")
	maxClients := flag.Int("max-clients", 128, "maximum simultaneous clients")
	flag.Parse()

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
	s := &tunnel.Server{ListenAddress: *listen, TLSConfig: tunnel.ServerTLSConfig(cert, pool), Device: dev, MaxClients: *maxClients}
	fmt.Printf("PQTunnel listening on %s; TLS 1.3 strict X25519MLKEM768; IPv4 packets only\n", *listen)
	if err := s.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fatalIf(err)
	}
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunneld:", err)
		os.Exit(1)
	}
}
