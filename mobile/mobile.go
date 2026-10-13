// Package mobile exposes a small API for gomobile. Android creates the TUN using VpnService
// and passes its file descriptor here.
package mobile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"

	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

// SocketProtector is implemented by the Android VpnService wrapper so the transport socket
// bypasses the VPN itself and cannot create a recursive tunnel.
type SocketProtector interface{ Protect(fd int32) bool }

type ClientHandle struct {
	cancel context.CancelFunc
	device *os.File
	done   chan struct{}
}

// StartClientFD starts the client asynchronously. The passed file descriptor must be a
// duplicated descriptor owned by the Go core, not the service's original ParcelFileDescriptor.
func StartClientFD(fd int32, serverAddress, serverName string, caPEM, certPEM, keyPEM []byte, localIP string, protector SocketProtector) (*ClientHandle, error) {
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(localIP)
	if err != nil || !ip.Is4() {
		return nil, fmt.Errorf("invalid local IPv4 address")
	}
	tlsCfg := tunnel.StrictTLS13Config()
	tlsCfg.RootCAs = rootCAs
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.ServerName = serverName
	file := os.NewFile(uintptr(fd), "pqtunnel-android-tun")
	if file == nil {
		return nil, fmt.Errorf("invalid TUN file descriptor")
	}
	var protect tunnel.SocketProtector
	if protector != nil {
		protect = func(rawFD uintptr) error {
			if rawFD > uintptr(2147483647) {
				return fmt.Errorf("socket descriptor overflow")
			}
			if !protector.Protect(int32(rawFD)) {
				return fmt.Errorf("VpnService.protect(fd) failed")
			}
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &ClientHandle{cancel: cancel, device: file, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		defer file.Close()
		_ = tunnel.RunClient(ctx, file, tunnel.ClientConfig{ServerAddress: serverAddress, ServerName: serverName, LocalIP: ip, TLSConfig: tlsCfg, ProtectSocket: protect})
	}()
	return h, nil
}

func (h *ClientHandle) Stop() {
	if h == nil {
		return
	}
	h.cancel()
	_ = h.device.Close()
	<-h.done
}
