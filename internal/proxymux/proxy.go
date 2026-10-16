package proxymux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxProxyConnections = 256
	proxyOpenTimeout    = 10 * time.Second
	proxyHandshakeLimit = 10 * time.Second
)

var blockedDirectPrefixes = mustPrefixes([]string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
})

func mustPrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

// ParseTCPPortSet parses a comma-separated list of TCP ports or inclusive
// port ranges, for example "80,443,8000-8010". An empty list is rejected.
func ParseTCPPortSet(value string) (map[uint16]struct{}, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("proxymux: at least one direct TCP port must be allowed")
	}
	out := make(map[uint16]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("proxymux: empty TCP port item")
		}
		lowText, highText, hasRange := strings.Cut(item, "-")
		low, err := parsePort(lowText)
		if err != nil {
			return nil, err
		}
		high := low
		if hasRange {
			high, err = parsePort(highText)
			if err != nil {
				return nil, err
			}
		}
		if high < low {
			return nil, fmt.Errorf("proxymux: invalid port range %q", item)
		}
		if int(high)-int(low) > 4096 {
			return nil, fmt.Errorf("proxymux: port range %q is too broad", item)
		}
		for port := uint32(low); port <= uint32(high); port++ {
			out[uint16(port)] = struct{}{}
		}
	}
	return out, nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("proxymux: invalid TCP port %q", value)
	}
	return uint16(n), nil
}

// ParseNamedAddresses parses "name=address,name2=address2" and rejects
// malformed or duplicate names. Values must be host:port addresses.
func ParseNamedAddresses(value string) (map[string]string, error) {
	out := make(map[string]string)
	if strings.TrimSpace(value) == "" {
		return out, nil
	}
	for _, item := range strings.Split(value, ",") {
		name, address, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || !validMappingID(name) {
			return nil, fmt.Errorf("proxymux: invalid mapping entry %q", item)
		}
		address = strings.TrimSpace(address)
		if _, _, err := splitHostPort(address); err != nil {
			return nil, fmt.Errorf("proxymux: mapping %q has an invalid address: %w", name, err)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("proxymux: duplicate mapping name %q", name)
		}
		out[name] = address
	}
	return out, nil
}

func validMappingID(value string) bool {
	if value == "" || len(value) > 64 || value == "." || value == ".." {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

func splitHostPort(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("expected host:port")
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// NewDirectTargetHandler returns a fixed-policy outgoing TCP handler. It only
// accepts Direct requests, enforces an explicit port allowlist and refuses
// private, loopback, link-local, metadata-adjacent and reserved address space.
// The target is resolved once and the chosen IP is dialed directly to prevent
// a second DNS lookup from changing the validated address.
func NewDirectTargetHandler(allowedPorts map[uint16]struct{}) OpenHandler {
	copiedPorts := make(map[uint16]struct{}, len(allowedPorts))
	for port := range allowedPorts {
		copiedPorts[port] = struct{}{}
	}
	return func(ctx context.Context, frameType Type, payload []byte) (net.Conn, error) {
		if frameType != TypeOpenDirect {
			return nil, errors.New("proxymux: Gateway only accepts Direct stream requests")
		}
		host, port, err := splitHostPort(string(payload))
		if err != nil {
			return nil, fmt.Errorf("proxymux: invalid Direct target: %w", err)
		}
		if _, allowed := copiedPorts[port]; !allowed {
			return nil, fmt.Errorf("proxymux: destination TCP port %d is not allowed", port)
		}
		return dialPublicTCP(ctx, host, port)
	}
}

// NewReverseTargetHandler returns a fixed reverse-target handler. A remote
// peer can select only a configured mapping name; it cannot supply an address.
func NewReverseTargetHandler(targets map[string]string) OpenHandler {
	copiedTargets := make(map[string]string, len(targets))
	for name, address := range targets {
		copiedTargets[name] = address
	}
	return func(ctx context.Context, frameType Type, payload []byte) (net.Conn, error) {
		if frameType != TypeOpenReverse {
			return nil, errors.New("proxymux: Dialer only accepts Reverse stream requests")
		}
		name := string(payload)
		if !validMappingID(name) {
			return nil, errors.New("proxymux: invalid reverse mapping name")
		}
		target, ok := copiedTargets[name]
		if !ok {
			return nil, errors.New("proxymux: reverse mapping is not configured")
		}
		dialer := net.Dialer{Timeout: proxyOpenTimeout, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, "tcp", target)
	}
}

func dialPublicTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	var ips []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{literal}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("proxymux: resolve Direct destination: %w", err)
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, errors.New("proxymux: Direct destination has no addresses")
	}
	for i, ip := range ips {
		ips[i] = ip.Unmap()
		if !publicUnicast(ips[i]) {
			return nil, errors.New("proxymux: Direct destination resolves to a private or reserved address")
		}
	}
	dialer := net.Dialer{Timeout: proxyOpenTimeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		network := "tcp4"
		if ip.Is6() {
			network = "tcp6"
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("proxymux: could not connect to Direct destination: %w", lastErr)
}

func publicUnicast(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedDirectPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// ListenSOCKS5 binds a local TCP proxy only to an explicit loopback IP.
func ListenSOCKS5(address string) (net.Listener, error) {
	host, _, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("proxymux: SOCKS5 listener must use a literal loopback IP")
	}
	return net.Listen("tcp", address)
}

// ServeSOCKS5Listener runs a no-auth SOCKS5 TCP CONNECT listener. The listener
// must already be bound to loopback. UDP ASSOCIATE and all other commands are
// rejected. It does not edit routes, TUN devices, sysctls, or firewall rules.
func ServeSOCKS5Listener(ctx context.Context, listener net.Listener, broker *SessionBroker) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil || broker == nil {
		return errors.New("proxymux: SOCKS5 listener and session broker are required")
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		_ = listener.Close()
		return errors.New("proxymux: refusing a non-loopback SOCKS5 listener")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, maxProxyConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-slots }()
				_ = serveSOCKS5Conn(ctx, c, broker)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func serveSOCKS5Conn(ctx context.Context, conn net.Conn, broker *SessionBroker) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(proxyHandshakeLimit))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		_ = writeFull(conn, []byte{5, 0xff})
		return errors.New("proxymux: invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_ = writeFull(conn, []byte{5, 0xff})
		return errors.New("proxymux: SOCKS5 no-auth method was not offered")
	}
	if err := writeFull(conn, []byte{5, 0}); err != nil {
		return err
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[2] != 0 {
		_ = writeSOCKS5Reply(conn, 1)
		return errors.New("proxymux: malformed SOCKS5 request")
	}
	if request[1] != 1 {
		_ = writeSOCKS5Reply(conn, 7)
		return errors.New("proxymux: SOCKS5 supports TCP CONNECT only")
	}
	host, err := readSOCKS5Host(conn, request[3])
	if err != nil {
		_ = writeSOCKS5Reply(conn, 8)
		return err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return err
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	if port == 0 {
		_ = writeSOCKS5Reply(conn, 8)
		return errors.New("proxymux: SOCKS5 destination port zero is invalid")
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	openCtx, cancel := context.WithTimeout(ctx, proxyOpenTimeout)
	stream, err := broker.Open(openCtx, TypeOpenDirect, []byte(target))
	cancel()
	if err != nil {
		_ = writeSOCKS5Reply(conn, 1)
		return err
	}
	defer stream.Close()
	if err := writeSOCKS5Reply(conn, 0); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return RelayTCP(ctx, conn, stream)
}

func readSOCKS5Host(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 1:
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom4(buf).String(), nil
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", errors.New("proxymux: empty SOCKS5 domain")
		}
		buf := make([]byte, int(size[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		if strings.IndexByte(string(buf), 0) >= 0 {
			return "", errors.New("proxymux: invalid SOCKS5 domain")
		}
		return string(buf), nil
	case 4:
		var buf [16]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom16(buf).String(), nil
	default:
		return "", errors.New("proxymux: unsupported SOCKS5 address type")
	}
}

func writeSOCKS5Reply(conn net.Conn, code byte) error {
	// An IPv4 unspecified bind address with port zero is valid when the proxy
	// does not expose a local bound address to the SOCKS client.
	return writeFull(conn, []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

// ListenReverse opens a listener at the exact configured address. It does not
// modify the firewall or routes; provider/host policy must already allow it.
func ListenReverse(address string) (net.Listener, error) {
	if _, _, err := splitHostPort(address); err != nil {
		return nil, err
	}
	return net.Listen("tcp", address)
}

// ServeReverseListener forwards connections received by listener through a
// fixed mapping name. The Dialer-side handler resolves that name to a
// preconfigured target; clients cannot specify arbitrary target addresses.
func ServeReverseListener(ctx context.Context, listener net.Listener, mapping string, broker *SessionBroker) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil || broker == nil || !validMappingID(mapping) {
		return errors.New("proxymux: reverse listener, mapping name, and session broker are required")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, maxProxyConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-slots }()
				_ = serveReverseConn(ctx, c, mapping, broker)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func serveReverseConn(ctx context.Context, conn net.Conn, mapping string, broker *SessionBroker) error {
	defer conn.Close()
	openCtx, cancel := context.WithTimeout(ctx, proxyOpenTimeout)
	stream, err := broker.Open(openCtx, TypeOpenReverse, []byte(mapping))
	cancel()
	if err != nil {
		return err
	}
	defer stream.Close()
	return RelayTCP(ctx, conn, stream)
}

// RelayTCP copies both directions, preserves TCP half-closes when supported,
// and closes both ends on cancellation or a non-EOF copy error.
func RelayTCP(ctx context.Context, left, right net.Conn) error {
	if left == nil || right == nil {
		return errors.New("proxymux: both relay connections are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	results := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil || errors.Is(err, io.EOF) {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = half.CloseWrite()
			}
		} else {
			closeBoth()
		}
		results <- err
	}
	go copyDirection(right, left)
	go copyDirection(left, right)

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && firstErr == nil {
				firstErr = err
				closeBoth()
			}
		case <-ctx.Done():
			closeBoth()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	closeBoth()
	return firstErr
}
