package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"os"
	"strconv"
	"strings"
	"os/signal"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminui"
	"github.com/hatinati2/PQTunnel/internal/manager"
	"github.com/hatinati2/PQTunnel/internal/speedtest"
)

func main() {
	roleText := os.Getenv("PQTUNNEL_MANAGER_ROLE")
	role := manager.Role(roleText)
	if role != manager.RoleGateway && role != manager.RoleDialer {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_ROLE must be gateway or dialer"))
	}
	listen := envString("PQTUNNEL_MANAGER_LISTEN", "127.0.0.1:9091")
	publicHost := os.Getenv("PQTUNNEL_MANAGER_PUBLIC_HOST")
	certFile := os.Getenv("PQTUNNEL_MANAGER_TLS_CERT")
	keyFile := os.Getenv("PQTUNNEL_MANAGER_TLS_KEY")
	isLoopback := adminui.ValidateLoopbackAddress(listen) == nil
	allowInsecurePublicHTTP := strings.EqualFold(os.Getenv("PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP"), "true")
	if !isLoopback {
		if allowInsecurePublicHTTP {
			fatalIf(validatePublicHTTPListener(listen, publicHost))
		} else {
			fatalIf(validatePublicTLSListener(listen, publicHost, certFile, keyFile))
		}
	}
	token := os.Getenv("PQTUNNEL_MANAGER_TOKEN")
	if len([]byte(token)) < 32 {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_TOKEN must contain at least 32 bytes"))
	}
	controlSocket := "/run/pqtunnel/control.sock"
	if role == manager.RoleDialer {
		controlSocket = "/run/pqtunnel/client-control.sock"
	}
	controller, err := manager.New(manager.Options{
		Role: role,
		ConfigPath: manager.ConfigPathForRole(role),
		BackupDir: "/var/lib/pqtunnel-manager/backups",
		IPCSocket: controlSocket,
		SpeedTestPeer: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_PEER"),
		SpeedTestToken: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN"),
	})
	fatalIf(err)
	handler, err := adminui.NewWithPublicAccess(token, controller, publicHost, allowInsecurePublicHTTP)
	fatalIf(err)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agentListen := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_LISTEN")
	agentToken := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN")
	if agentListen != "" || agentToken != "" {
		// Misconfigured optional benchmarking must not take the management UI
		// offline; keep the panel available so the operator can repair config.
		if agentListen == "" || len([]byte(agentToken)) < 32 {
			fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent disabled: set both the private listen address and a separate token of at least 32 bytes")
		} else if err := controller.ValidateSpeedTestListener(agentListen, agentToken); err != nil {
			fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent disabled:", err)
		} else {
			go func() {
				if err := speedtest.ServeAgent(ctx, agentListen, agentToken); err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent:", err)
				}
			}()
		}
	}
	listener, err := net.Listen("tcp", listen)
	fatalIf(err)
	server := &http.Server{
		Addr: listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second,
		WriteTimeout: 310 * time.Second,
		IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if isLoopback {
		fmt.Printf("PQTunnel manager (%s) available at http://%s/ (loopback-only; token protected)\n", role, listen)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatalIf(err)
		}
	} else if allowInsecurePublicHTTP {
		fmt.Fprintf(os.Stderr, "WARNING: PQTunnel manager (%s) is exposed over INSECURE plaintext HTTP at http://%s/; credentials and session cookies can be intercepted. Disable this mode as soon as HTTPS is configured.\n", role, publicHost)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatalIf(err)
		}
	} else {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		fmt.Printf("PQTunnel manager (%s) available at https://%s/ (TLS enabled; host allowlisted)\n", role, publicHost)
		if err := server.ServeTLS(listener, certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatalIf(err)
		}
	}
}

func validatePublicHTTPListener(address, publicHost string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("public manager listen address must be IP:port (for example 0.0.0.0:9091)")
	}
	listenIP, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("public manager listener must use a literal IP or wildcard address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("public manager listen port must be between 1 and 65535")
	}
	ip, err := netip.ParseAddr(publicHost)
	if err != nil || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("PQTUNNEL_MANAGER_PUBLIC_HOST must be a public, non-loopback literal IP address")
	}
	if !listenIP.IsUnspecified() && listenIP != ip {
		return fmt.Errorf("bind to 0.0.0.0:9091 or the same IP configured in PQTUNNEL_MANAGER_PUBLIC_HOST")
	}
	return nil
}

func validatePublicTLSListener(address, publicHost, certFile, keyFile string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("public manager listen address must be IP:port (for example 0.0.0.0:9091)")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("public manager listener must use a literal IP or wildcard address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("public manager listen port must be between 1 and 65535")
	}
	if publicHost == "" {
		return fmt.Errorf("PQTUNNEL_MANAGER_PUBLIC_HOST must be the public IP address covered by the TLS certificate")
	}
	ip, err := netip.ParseAddr(publicHost)
	if err != nil || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("PQTUNNEL_MANAGER_PUBLIC_HOST must be a public, non-loopback literal IP address")
	}
	listenIP, _ := netip.ParseAddr(host)
	if !listenIP.IsUnspecified() && listenIP != ip {
		return fmt.Errorf("bind to 0.0.0.0:9091 or the same IP configured in PQTUNNEL_MANAGER_PUBLIC_HOST")
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("public manager access requires PQTUNNEL_MANAGER_TLS_CERT and PQTUNNEL_MANAGER_TLS_KEY; refusing plaintext HTTP")
	}
	if !filepath.IsAbs(certFile) || !filepath.IsAbs(keyFile) {
		return fmt.Errorf("TLS certificate and key paths must be absolute")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("cannot load TLS certificate/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("cannot parse TLS leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(publicHost); err != nil {
		return fmt.Errorf("TLS certificate must contain the configured public IP in its IP SAN: %w", err)
	}
	return nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-manager:", err)
		os.Exit(1)
	}
}
