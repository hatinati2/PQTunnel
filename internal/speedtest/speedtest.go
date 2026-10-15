package speedtest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxMiB = 32
	minBytes = 1 << 20
	maxBytes = MaxMiB << 20
	chunkSize = 32 << 10
)

type Result struct {
	Peer            string  `json:"peer"`
	SizeMiB         int     `json:"size_mib"`
	RTTMillis       float64 `json:"rtt_ms"`
	UploadMbps      float64 `json:"upload_mbps"`
	DownloadMbps    float64 `json:"download_mbps"`
	UploadSeconds   float64 `json:"upload_seconds"`
	DownloadSeconds float64 `json:"download_seconds"`
	CompletedAt     time.Time `json:"completed_at"`
}

type Handler struct {
	token  []byte
	active chan struct{}
}

type transferResponse struct {
	Bytes int64 `json:"bytes"`
}

func NewHandler(token string) (*Handler, error) {
	if len([]byte(token)) < 32 {
		return nil, errors.New("speed-test token must contain at least 32 bytes")
	}
	return &Handler{token: []byte(token), active: make(chan struct{}, 1)}, nil
}

// ValidatePrivateEndpoint requires a literal RFC1918/ULA address, never a
// hostname, wildcard, loopback, link-local, multicast or public IP.
func ValidatePrivateEndpoint(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.New("speed-test endpoint must be a literal private IP and port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("speed-test port must be between 1 and 65535")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsValid() || !ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return errors.New("speed-test endpoint must use a private literal tunnel IP")
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/v1/health" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	case r.URL.Path == "/v1/ping" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	case r.URL.Path == "/v1/upload" && r.Method == http.MethodPost:
		h.handleUpload(w, r)
	case r.URL.Path == "/v1/download" && r.Method == http.MethodGet:
		h.handleDownload(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h *Handler) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(value, prefix)), h.token) == 1
}

func (h *Handler) beginTransfer(w http.ResponseWriter) bool {
	select {
	case h.active <- struct{}{}:
		return true
	default:
		http.Error(w, "speed test already running", http.StatusTooManyRequests)
		return false
	}
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	size, ok := requestedBytes(w, r)
	if !ok {
		return
	}
	if r.ContentLength != size {
		http.Error(w, "content length must match requested bytes", http.StatusBadRequest)
		return
	}
	if !h.beginTransfer(w) {
		return
	}
	defer func() { <-h.active }()
	n, err := io.CopyN(io.Discard, r.Body, size)
	if err != nil || n != size {
		http.Error(w, "incomplete upload", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(transferResponse{Bytes: n})
}

func (h *Handler) handleDownload(w http.ResponseWriter, r *http.Request) {
	size, ok := requestedBytes(w, r)
	if !ok {
		return
	}
	if !h.beginTransfer(w) {
		return
	}
	defer func() { <-h.active }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	buf := make([]byte, chunkSize)
	var sent int64
	for sent < size {
		next := int64(len(buf))
		if next > size-sent {
			next = size - sent
		}
		n, err := w.Write(buf[:next])
		sent += int64(n)
		if err != nil || int64(n) != next {
			return
		}
	}
}

func requestedBytes(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := r.URL.Query().Get("bytes")
	size, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || size < minBytes || size > maxBytes {
		http.Error(w, "bytes must be between 1 MiB and 32 MiB", http.StatusBadRequest)
		return 0, false
	}
	return size, true
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func Run(ctx context.Context, endpoint, token string, sizeMiB int) (Result, error) {
	if err := ValidatePrivateEndpoint(endpoint); err != nil {
		return Result{}, err
	}
	if len([]byte(token)) < 32 {
		return Result{}, errors.New("speed-test token must contain at least 32 bytes on both servers")
	}
	if sizeMiB < 1 || sizeMiB > MaxMiB {
		return Result{}, fmt.Errorf("speed-test size must be between 1 and %d MiB", MaxMiB)
	}
	base := "http://" + endpoint
	return runAgainst(ctx, endpoint, base, token, sizeMiB)
}

func runAgainst(ctx context.Context, endpoint, baseURL, token string, sizeMiB int) (Result, error) {
	result := Result{Peer: endpoint, SizeMiB: sizeMiB}
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression: true,
		MaxIdleConns: 2,
		MaxIdleConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout: 300 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request := func(method, path string, body io.Reader, size int64) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
		if err != nil { return nil, err }
		req.Header.Set("Authorization", "Bearer "+token)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = size
		}
		return client.Do(req)
	}

	resp, err := request(http.MethodGet, "/v1/health", nil, 0)
	if err != nil { return result, fmt.Errorf("connect to speed-test agent over tunnel: %w", err) }
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return result, fmt.Errorf("peer speed-test agent returned HTTP %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	const rttSamples = 5
	rtts := make([]float64, 0, rttSamples)
	for i := 0; i < rttSamples; i++ {
		start := time.Now()
		resp, err = request(http.MethodGet, "/v1/ping", nil, 0)
		if err != nil { return result, fmt.Errorf("RTT probe %d failed: %w", i+1, err) }
		_, copyErr := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if copyErr != nil || resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("RTT probe %d returned an invalid response", i+1)
		}
		rtts = append(rtts, float64(time.Since(start).Microseconds())/1000)
	}
	sort.Float64s(rtts)
	result.RTTMillis = rtts[len(rtts)/2]

	byteCount := int64(sizeMiB) << 20
	start := time.Now()
	resp, err = request(http.MethodPost, "/v1/upload?bytes="+strconv.FormatInt(byteCount, 10), io.LimitReader(zeroReader{}, byteCount), byteCount)
	if err != nil { return result, fmt.Errorf("upload test failed: %w", err) }
	var upload transferResponse
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&upload)
	_ = resp.Body.Close()
	uploadElapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK || decodeErr != nil || upload.Bytes != byteCount || uploadElapsed <= 0 {
		return result, errors.New("peer returned an invalid upload-test result")
	}
	result.UploadSeconds = uploadElapsed.Seconds()
	result.UploadMbps = float64(byteCount*8) / uploadElapsed.Seconds() / 1_000_000

	start = time.Now()
	resp, err = request(http.MethodGet, "/v1/download?bytes="+strconv.FormatInt(byteCount, 10), nil, 0)
	if err != nil { return result, fmt.Errorf("download test failed: %w", err) }
	if resp.StatusCode != http.StatusOK || resp.ContentLength != byteCount {
		_ = resp.Body.Close()
		return result, errors.New("peer returned an invalid download-test response")
	}
	downloaded, copyErr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	downloadElapsed := time.Since(start)
	if copyErr != nil || downloaded != byteCount || downloadElapsed <= 0 {
		return result, errors.New("download test did not transfer the requested bytes")
	}
	result.DownloadSeconds = downloadElapsed.Seconds()
	result.DownloadMbps = float64(byteCount*8) / downloadElapsed.Seconds() / 1_000_000
	result.CompletedAt = time.Now().UTC()
	return result, nil
}

// ServeAgent retries binding while the tunnel IP is not yet assigned. It only
// listens on the configured private IP, never a wildcard or public interface.
func ServeAgent(ctx context.Context, address, token string) error {
	if err := ValidatePrivateEndpoint(address); err != nil { return err }
	ip, _, err := ParseEndpointAddress(address)
	if err != nil { return err }
	handler, err := NewHandler(token)
	if err != nil { return err }
	for {
		// Wait until the configured literal address is assigned specifically
		// to the tunnel interface. This avoids accidentally exposing the test
		// agent on a physical private LAN address that overlaps a broad prefix.
		if !interfaceHasAddress("pqtun0", ip) {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(3 * time.Second):
				continue
			}
		}
		ln, err := net.Listen("tcp", address)
		if err == nil {
			server := &http.Server{
				Handler: handler,
				ReadHeaderTimeout: 3 * time.Second,
				ReadTimeout: 300 * time.Second,
				WriteTimeout: 300 * time.Second,
				IdleTimeout: 15 * time.Second,
				MaxHeaderBytes: 8 << 10,
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ln) }()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = server.Shutdown(shutdownCtx)
				cancel()
				_ = ln.Close()
				return nil
			case serveErr := <-done:
				_ = ln.Close()
				if ctx.Err() != nil || errors.Is(serveErr, http.ErrServerClosed) { return nil }
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

func interfaceHasAddress(name string, want netip.Addr) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil { return false }
	addrs, err := iface.Addrs()
	if err != nil { return false }
	for _, raw := range addrs {
		value := strings.Split(raw.String(), "%")[0]
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if prefix.Addr().Unmap() == want.Unmap() { return true }
			continue
		}
		if address, err := netip.ParseAddr(value); err == nil && address.Unmap() == want.Unmap() {
			return true
		}
	}
	return false
}

func ParseEndpointAddress(address string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil { return netip.Addr{}, 0, errors.New("expected private IP:port") }
	ip, err := netip.ParseAddr(host)
	if err != nil { return netip.Addr{}, 0, errors.New("speed-test host must be a literal IP") }
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 { return netip.Addr{}, 0, errors.New("speed-test port must be between 1 and 65535") }
	return ip, uint16(port), nil
}

// SafeBaseURL is used only by tests and enforces an absolute HTTP(S) URL without
// credentials or fragments before a request can be sent.
func SafeBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return errors.New("invalid speed-test base URL")
	}
	return nil
}

var _ sync.Locker = (*sync.Mutex)(nil)
