package speedtest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidatePrivateEndpoint(t *testing.T) {
	valid := []string{"10.66.0.2:9109", "192.168.50.2:9109", "[fd42:7061:7475::2]:9109"}
	for _, value := range valid {
		if err := ValidatePrivateEndpoint(value); err != nil {
			t.Errorf("%q rejected: %v", value, err)
		}
	}
	invalid := []string{
		"127.0.0.1:9109", "0.0.0.0:9109", "192.0.2.4:9109",
		"8.8.8.8:9109", "example.test:9109", "10.66.0.2:0",
		"169.254.2.3:9109", "224.0.0.1:9109",
	}
	for _, value := range invalid {
		if err := ValidatePrivateEndpoint(value); err == nil {
			t.Errorf("%q unexpectedly accepted", value)
		}
	}
}

func TestHandlerRequiresBearerTokenAndBoundsTransfers(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	h, err := NewHandler(token)
	if err != nil { t.Fatal(err) }

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d, want 401", unauthorized.Code)
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/upload?bytes=0"},
		{http.MethodPost, "/v1/upload?bytes=999"},
		{http.MethodGet, "/v1/download?bytes=999999999999"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s status=%d, want 400", tc.method, tc.path, rec.Code)
		}
	}
}

func TestRunAgainstTunnelAgentReportsRTTAndBidirectionalThroughput(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	h, err := NewHandler(token)
	if err != nil { t.Fatal(err) }
	server := httptest.NewServer(h)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := runAgainst(ctx, "10.66.0.2:9109", server.URL, token, 1)
	if err != nil { t.Fatalf("run speed test: %v", err) }
	if result.Peer != "10.66.0.2:9109" || result.SizeMiB != 1 {
		t.Fatalf("unexpected result identity/size: %#v", result)
	}
	if result.RTTMillis <= 0 || result.UploadMbps <= 0 || result.DownloadMbps <= 0 {
		t.Fatalf("expected positive RTT and throughput values: %#v", result)
	}
	if result.UploadSeconds <= 0 || result.DownloadSeconds <= 0 || result.CompletedAt.IsZero() {
		t.Fatalf("expected complete timing metadata: %#v", result)
	}
}

func TestRunRejectsPublicTargetsAndOversizedRequests(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	if _, err := Run(context.Background(), "8.8.8.8:9109", token, 1); err == nil {
		t.Fatal("public endpoint must be rejected before dialing")
	}
	if _, err := Run(context.Background(), "10.66.0.2:9109", token, MaxMiB+1); err == nil {
		t.Fatal("oversized speed test must be rejected")
	}
}

func TestAgentDoesNotAcceptMalformedBearerHeader(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	h, err := NewHandler(token)
	if err != nil { t.Fatal(err) }
	for _, header := range []string{token, "Bearer", "Bearer "+token+"x"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("authorization %q status=%d, want 401", strings.TrimSpace(header), rec.Code)
		}
	}
}

func TestSpeedTestErrorMessageDoesNotIncludeToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	_, err := Run(context.Background(), "10.66.0.2:9109", token, -1)
	if err == nil { t.Fatal("invalid size must be rejected") }
	if strings.Contains(err.Error(), token) { t.Fatal(fmt.Sprintf("error exposed token: %v", err)) }
}
