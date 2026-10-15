package adminui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type fakeController struct {
	snapshot     adminapi.Snapshot
	disconnected []string
}

type fakeManagerController struct {
	*fakeController
	view adminapi.ManagerSnapshot
	actions []string
	applied []adminapi.TunnelConfiguration
	speedSizes []int
	speedResult adminapi.SpeedTestResult
	serviceErr error
	configErr error
	speedErr error
}

func (f *fakeManagerController) ManagementSnapshot() adminapi.ManagerSnapshot { return f.view }
func (f *fakeManagerController) ServiceAction(_ context.Context, action string) error {
	f.actions = append(f.actions, action)
	return f.serviceErr
}
func (f *fakeManagerController) ApplyConfiguration(_ context.Context, cfg adminapi.TunnelConfiguration) error {
	f.applied = append(f.applied, cfg)
	return f.configErr
}
func (f *fakeManagerController) RunSpeedTest(_ context.Context, sizeMiB int) (adminapi.SpeedTestResult, error) {
	f.speedSizes = append(f.speedSizes, sizeMiB)
	return f.speedResult, f.speedErr
}

func managerSession(t *testing.T, h *Handler, token string) (*http.Cookie, string) {
	t.Helper()
	loginValues := url.Values{"token": {token}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/login", strings.NewReader(loginValues.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusSeeOther {
		t.Fatalf("manager test login status=%d", loginResp.Code)
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) == 0 { t.Fatal("manager login cookie missing") }
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	req.AddCookie(cookies[0])
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	matches := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(resp.Body.String())
	if resp.Code != http.StatusOK || len(matches) != 2 {
		t.Fatalf("manager dashboard unavailable: status=%d body=%s", resp.Code, resp.Body.String())
	}
	return cookies[0], matches[1]
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
	if !strings.Contains(dashboardResp.Body.String(), "به‌روزرسانی وضعیت") ||
		!strings.Contains(dashboardResp.Body.String(), `<details class="disconnect">`) ||
		!strings.Contains(dashboardResp.Body.String(), "تأیید قطع اتصال") {
		t.Fatal("dashboard must offer manual refresh and a second step before disconnect")
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

func postLogin(t *testing.T, h *Handler, token, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	values := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/login", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.RemoteAddr = remoteAddr
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	return resp
}

func TestLoginRateLimitsRepeatedInvalidTokensPerClient(t *testing.T) {
	const token = "a-very-long-test-token-value-123456"
	h, err := New(token, &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	const clientA = "127.0.0.1:12000"
	for i := 1; i <= loginFailureLimit; i++ {
		resp := postLogin(t, h, "incorrect-token", clientA)
		if i < loginFailureLimit && resp.Code != http.StatusOK {
			t.Fatalf("attempt %d status=%d, want %d", i, resp.Code, http.StatusOK)
		}
		if i == loginFailureLimit {
			if resp.Code != http.StatusTooManyRequests || resp.Header().Get("Retry-After") != "60" {
				t.Fatalf("limit attempt status=%d retry-after=%q", resp.Code, resp.Header().Get("Retry-After"))
			}
		}
	}
	if resp := postLogin(t, h, token, clientA); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("correct token must remain blocked during cooldown, got %d", resp.Code)
	}
	if resp := postLogin(t, h, token, "127.0.0.2:12001"); resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/" {
		t.Fatalf("separate client login status=%d location=%q", resp.Code, resp.Header().Get("Location"))
	}
}

func TestSuccessfulLoginResetsFailedAttempts(t *testing.T) {
	const token = "another-long-token-for-unit-test-456"
	h, err := New(token, &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	const client = "127.0.0.1:13000"
	for i := 0; i < loginFailureLimit-1; i++ {
		if resp := postLogin(t, h, "wrong", client); resp.Code != http.StatusOK {
			t.Fatalf("pre-login invalid attempt status=%d", resp.Code)
		}
	}
	if resp := postLogin(t, h, token, client); resp.Code != http.StatusSeeOther {
		t.Fatalf("correct login status=%d, want redirect", resp.Code)
	}
	for i := 0; i < loginFailureLimit-1; i++ {
		if resp := postLogin(t, h, "wrong-again", client); resp.Code != http.StatusOK {
			t.Fatalf("failed attempts were not reset after login; attempt %d status=%d", i+1, resp.Code)
		}
	}
}

func TestExpiredSessionIsRemovedAndRedirectsToLogin(t *testing.T) {
	h, err := New(strings.Repeat("e", 32), &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.sessions["expired-session"] = session{CSRF: "expired-csrf", ExpiresAt: time.Now().Add(-time.Second)}
	h.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired-session"})
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/login" {
		t.Fatalf("expired session status=%d location=%q", resp.Code, resp.Header().Get("Location"))
	}
	h.mu.Lock()
	_, remains := h.sessions["expired-session"]
	h.mu.Unlock()
	if remains {
		t.Fatal("expired session was not removed")
	}
}

func TestLoginAttemptTableOverflowFailsClosed(t *testing.T) {
	const token = "test-token-with-at-least-32-characters"
	h, err := New(token, &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxLoginEntries; i++ {
		remote := "127.0.0." + strconv.Itoa(i) + ":12000"
		if resp := postLogin(t, h, "wrong-token", remote); resp.Code != http.StatusOK {
			t.Fatalf("seed attempt %d status=%d, want 200", i, resp.Code)
		}
	}
	overflow := postLogin(t, h, "wrong-token", "127.0.0.129:12000")
	if overflow.Code != http.StatusTooManyRequests || overflow.Header().Get("Retry-After") != "60" {
		t.Fatalf("overflow status=%d retry-after=%q", overflow.Code, overflow.Header().Get("Retry-After"))
	}
	if resp := postLogin(t, h, token, "127.0.0.130:12000"); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow mode must fail closed for other clients, got %d", resp.Code)
	}
}

func TestRejectsDNSRebindingHostEvenWhenOriginMatchesHost(t *testing.T) {
	const token = "test-token-that-is-at-least-32-characters"
	h, err := New(token, &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "http://admin.attacker.invalid/login", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://admin.attacker.invalid")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("matching attacker-controlled Host/Origin status=%d, want 403", resp.Code)
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


func TestSecurityHeadersPresentOnLoginAndUnknownPath(t *testing.T) {
	h, err := New(strings.Repeat("h", 32), &fakeController{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/login", "/missing"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		headers := map[string]string{
			"Cache-Control":             "no-store",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "no-referrer",
			"Content-Security-Policy":   "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
		}
		for name, want := range headers {
			if got := resp.Header().Get(name); got != want {
				t.Errorf("%s %s header=%q, want %q", path, name, got, want)
			}
		}
	}
}

func TestDisconnectRejectsInvalidCSRFAndOversizedBody(t *testing.T) {
	const token = "token-for-csrf-and-body-limit-regression-test"
	controller := &fakeController{snapshot: adminapi.Snapshot{
		Running: true, MaxClients: 1,
		Peers: []adminapi.Peer{{Identity: "peer-1", ConnectedFor: "5s"}},
	}}
	h, err := New(token, controller)
	if err != nil {
		t.Fatal(err)
	}
	loginResp := postLogin(t, h, token, "127.0.0.1:14000")
	if loginResp.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d, want redirect", loginResp.Code)
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies=%v, want one session cookie", cookies)
	}

	dashboardReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	dashboardReq.AddCookie(cookies[0])
	dashboardResp := httptest.NewRecorder()
	h.ServeHTTP(dashboardResp, dashboardReq)
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(dashboardResp.Body.String())
	if len(match) != 2 {
		t.Fatal("dashboard did not include CSRF token")
	}

	badCSRF := url.Values{"identity": {"peer-1"}, "csrf": {"invalid"}}
	badReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/peers/disconnect", strings.NewReader(badCSRF.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.Header.Set("Origin", "http://127.0.0.1")
	badReq.AddCookie(cookies[0])
	badResp := httptest.NewRecorder()
	h.ServeHTTP(badResp, badReq)
	if badResp.Code != http.StatusBadRequest || len(controller.disconnected) != 0 {
		t.Fatalf("invalid CSRF status=%d disconnected=%v, want 400 and no action", badResp.Code, controller.disconnected)
	}

	oversized := url.Values{
		"identity": {"peer-1"},
		"csrf":     {match[1]},
		"padding":  {strings.Repeat("x", 5000)},
	}
	largeReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/peers/disconnect", strings.NewReader(oversized.Encode()))
	largeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	largeReq.Header.Set("Origin", "http://127.0.0.1")
	largeReq.AddCookie(cookies[0])
	largeResp := httptest.NewRecorder()
	h.ServeHTTP(largeResp, largeReq)
	if largeResp.Code != http.StatusBadRequest || len(controller.disconnected) != 0 {
		t.Fatalf("oversized form status=%d disconnected=%v, want 400 and no action", largeResp.Code, controller.disconnected)
	}
}


func TestStandaloneManagerDashboardAndLifecycleActions(t *testing.T) {
	const token = "standalone-manager-test-token-012345"
	base := &fakeController{snapshot: adminapi.Snapshot{
		Running: true, ListenAddress: "0.0.0.0:8443", MaxClients: 1,
	}}
	manager := &fakeManagerController{
		fakeController: base,
		view: adminapi.ManagerSnapshot{
			Role: "gateway", ServiceUnit: "pqtunneld.service", ActiveState: "active",
			SubState: "running", MainPID: "123", ConfigReady: true,
			Config: adminapi.TunnelConfiguration{
				ListenAddress: "0.0.0.0:8443", MaxClients: 1,
				PeerPrefixes: "10.66.0.2/32", LocalPrefixes: "10.66.0.1/32",
				PeerIdentity: "dialer-1", AllowedDstPorts: "tcp:443,tcp:9109",
			},
			SpeedTestPeer: "10.66.0.2:9109", SpeedTestReady: true,
			LastSpeedTest: &adminapi.SpeedTestResult{
				Peer: "10.66.0.2:9109", SizeMiB: 4, RTTMillis: 9.5,
				UploadMbps: 80, DownloadMbps: 75, UploadSeconds: .4, DownloadSeconds: .45,
				CompletedAt: "2026-10-15T12:00:00Z",
			},
		},
		speedResult: adminapi.SpeedTestResult{Peer: "10.66.0.2:9109", SizeMiB: 2, RTTMillis: 10, UploadMbps: 50, DownloadMbps: 45},
	}
	h, err := New(token, manager)
	if err != nil { t.Fatal(err) }
	cookie, csrf := managerSession(t, h, token)

	dashboardReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	dashboardReq.AddCookie(cookie)
	dashboardResp := httptest.NewRecorder()
	h.ServeHTTP(dashboardResp, dashboardReq)
	for _, expected := range []string{
		"pqtunneld.service", "/service/action", "/config/apply", "/speedtest/run",
		"10.66.0.2:9109", "80.00 Mbps", "75.00 Mbps",
	} {
		if !strings.Contains(dashboardResp.Body.String(), expected) {
			t.Errorf("manager dashboard lacks %q", expected)
		}
	}

	post := func(path string, values url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://127.0.0.1")
		req.AddCookie(cookie)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		return resp
	}

	serviceValues := url.Values{"csrf": {csrf}, "action": {"restart"}, "confirm": {"yes"}}
	serviceResp := post("/service/action", serviceValues)
	if serviceResp.Code != http.StatusSeeOther || serviceResp.Header().Get("Location") != "/?notice=service-restart" {
		t.Fatalf("restart response status=%d location=%q", serviceResp.Code, serviceResp.Header().Get("Location"))
	}
	if len(manager.actions) != 1 || manager.actions[0] != "restart" {
		t.Fatalf("unexpected service actions: %v", manager.actions)
	}

	configValues := url.Values{
		"csrf": {csrf}, "confirm": {"yes"},
		"listen_address": {"0.0.0.0:8443"}, "peer_prefixes": {"10.66.0.2/32"},
		"local_prefixes": {"10.66.0.1/32"}, "peer_identity": {"dialer-1"},
		"allowed_dst_ports": {"tcp:443,tcp:9109"},
	}
	configResp := post("/config/apply", configValues)
	if configResp.Code != http.StatusSeeOther || len(manager.applied) != 1 {
		t.Fatalf("config apply status=%d applied=%d", configResp.Code, len(manager.applied))
	}
	if manager.applied[0].ListenAddress != "0.0.0.0:8443" || manager.applied[0].MaxClients != 1 {
		t.Fatalf("unexpected config forwarded to controller: %#v", manager.applied[0])
	}

	speedValues := url.Values{"csrf": {csrf}, "confirm": {"yes"}, "megabytes": {"2"}}
	speedResp := post("/speedtest/run", speedValues)
	if speedResp.Code != http.StatusSeeOther || speedResp.Header().Get("Location") != "/?notice=speedtest-completed" {
		t.Fatalf("speed test status=%d location=%q", speedResp.Code, speedResp.Header().Get("Location"))
	}
	if len(manager.speedSizes) != 1 || manager.speedSizes[0] != 2 {
		t.Fatalf("unexpected speed-test sizes: %v", manager.speedSizes)
	}
}

func TestStandaloneManagerActionsRequireCSRFAndConfirmation(t *testing.T) {
	const token = "standalone-manager-test-token-012345"
	manager := &fakeManagerController{fakeController: &fakeController{}, view: adminapi.ManagerSnapshot{Role: "dialer"}}
	h, err := New(token, manager)
	if err != nil { t.Fatal(err) }
	cookie, csrf := managerSession(t, h, token)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/service/action", strings.NewReader(url.Values{
		"csrf": {"wrong"}, "action": {"stop"}, "confirm": {"yes"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest || len(manager.actions) != 0 {
		t.Fatalf("bad CSRF should reject action: status=%d calls=%v", resp.Code, manager.actions)
	}

	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/service/action", strings.NewReader(url.Values{
		"csrf": {csrf}, "action": {"stop"}, "confirm": {"no"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest || len(manager.actions) != 0 {
		t.Fatalf("missing explicit confirmation should reject action: status=%d calls=%v", resp.Code, manager.actions)
	}
}
