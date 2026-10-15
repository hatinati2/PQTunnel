package adminui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type fakeController struct {
	snapshot     adminapi.Snapshot
	disconnected []string
}

func (f *fakeController) AdminSnapshot() adminapi.Snapshot { return f.snapshot }
func (f *fakeController) DisconnectPeer(identity string) bool {
	for _, p := range f.snapshot.Peers {
		if p.Identity == identity {
			f.disconnected = append(f.disconnected, identity)
			return true
		}
	}
	return false
}

func TestNewRequiresLongTokenAndController(t *testing.T) {
	if _, err := New(strings.Repeat("x", 31), &fakeController{}); err == nil {
		t.Fatal("expected short token to be rejected")
	}
	if _, err := New(strings.Repeat("x", 32), nil); err == nil {
		t.Fatal("expected nil controller to be rejected")
	}
}

func TestValidateLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if err := ValidateLoopbackAddress(addr); err != nil {
			t.Errorf("ValidateLoopbackAddress(%q): %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:9090", ":9090", "192.0.2.10:9090", "localhost:9090", "127.0.0.1:0", "127.0.0.1:abc"} {
		if err := ValidateLoopbackAddress(addr); err == nil {
			t.Errorf("ValidateLoopbackAddress(%q) unexpectedly succeeded", addr)
		}
	}
}

func TestLoginDashboardDisconnectAndLogout(t *testing.T) {
	token := strings.Repeat("x", 32)
	controller := &fakeController{snapshot: adminapi.Snapshot{
		Running: true, Uptime: "12s", ListenAddress: "127.0.0.1:8443", MaxClients: 8,
		Peers: []adminapi.Peer{{Identity: "peer-1", ConnectedFor: "5s"}},
	}}
	h, err := New(token, controller)
	if err != nil {
		t.Fatal(err)
	}

	loginValues := url.Values{"token": {token}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/login", strings.NewReader(loginValues.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusSeeOther || loginResp.Header().Get("Location") != "/" {
		t.Fatalf("login status=%d location=%q", loginResp.Code, loginResp.Header().Get("Location"))
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected hardened session cookie, got %#v", cookies)
	}
	cookie := cookies[0]

	dashboardReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	dashboardReq.AddCookie(cookie)
	dashboardResp := httptest.NewRecorder()
	h.ServeHTTP(dashboardResp, dashboardReq)
	if dashboardResp.Code != http.StatusOK || !strings.Contains(dashboardResp.Body.String(), "peer-1") {
		t.Fatalf("dashboard not rendered: status=%d", dashboardResp.Code)
	}
	matches := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(dashboardResp.Body.String())
	if len(matches) != 2 {
		t.Fatal("dashboard did not include CSRF token")
	}

	disconnectValues := url.Values{"identity": {"peer-1"}, "csrf": {matches[1]}}
	disconnectReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/peers/disconnect", strings.NewReader(disconnectValues.Encode()))
	disconnectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	disconnectReq.Header.Set("Origin", "http://127.0.0.1")
	disconnectReq.AddCookie(cookie)
	disconnectResp := httptest.NewRecorder()
	h.ServeHTTP(disconnectResp, disconnectReq)
	if disconnectResp.Code != http.StatusSeeOther || len(controller.disconnected) != 1 || controller.disconnected[0] != "peer-1" {
		t.Fatalf("disconnect failed: status=%d peers=%v", disconnectResp.Code, controller.disconnected)
	}

	logoutValues := url.Values{"csrf": {matches[1]}}
	logoutReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/logout", strings.NewReader(logoutValues.Encode()))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutReq.Header.Set("Origin", "http://127.0.0.1")
	logoutReq.AddCookie(cookie)
	logoutResp := httptest.NewRecorder()
	h.ServeHTTP(logoutResp, logoutReq)
	if logoutResp.Code != http.StatusSeeOther || logoutResp.Header().Get("Location") != "/login" {
		t.Fatalf("logout status=%d location=%q", logoutResp.Code, logoutResp.Header().Get("Location"))
	}
}

func TestRejectsCrossOriginLoginAndDisconnect(t *testing.T) {
	token := strings.Repeat("y", 32)
	controller := &fakeController{snapshot: adminapi.Snapshot{
		Running: true, MaxClients: 1,
		Peers: []adminapi.Peer{{Identity: "peer-1"}},
	}}
	h, err := New(token, controller)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://attacker.invalid")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status=%d, want 403", resp.Code)
	}

	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	cookie := loginResp.Result().Cookies()[0]
	dashboardReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	dashboardReq.AddCookie(cookie)
	dashboardResp := httptest.NewRecorder()
	h.ServeHTTP(dashboardResp, dashboardReq)
	matches := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(dashboardResp.Body.String())
	form = url.Values{"identity": {"peer-1"}, "csrf": {matches[1]}}
	disconnectReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/peers/disconnect", strings.NewReader(form.Encode()))
	disconnectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	disconnectReq.Header.Set("Origin", "http://attacker.invalid")
	disconnectReq.AddCookie(cookie)
	disconnectResp := httptest.NewRecorder()
	h.ServeHTTP(disconnectResp, disconnectReq)
	if disconnectResp.Code != http.StatusForbidden || len(controller.disconnected) != 0 {
		t.Fatalf("cross-origin disconnect status=%d peers=%v", disconnectResp.Code, controller.disconnected)
	}
}

func TestDashboardRedirectsUnauthenticatedRequests(t *testing.T) {
	h, err := New(strings.Repeat("z", 32), &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/login" {
		t.Fatalf("status=%d location=%q", resp.Code, resp.Header().Get("Location"))
	}
}
