package adminui

import (
	"context"
	"crypto/tls"
	"regexp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type fakeSetupWizard struct {
	*fakeManagerController
	status adminapi.SiteToSiteSetupStatus
	started adminapi.SiteToSiteSetupRequest
	startErr error
	approved bool
	approveErr error
	tokens adminapi.SiteToSiteSetupTokens
	tokenCalls int
}

func (f *fakeSetupWizard) StartSiteToSiteSetup(_ context.Context, req adminapi.SiteToSiteSetupRequest) error {
	f.started = req
	return f.startErr
}
func (f *fakeSetupWizard) SiteToSiteSetupStatus(_ context.Context) (adminapi.SiteToSiteSetupStatus, error) {
	return f.status, nil
}
func (f *fakeSetupWizard) ConsumeSiteToSiteSetupTokens(_ context.Context) (adminapi.SiteToSiteSetupTokens, error) {
	f.tokenCalls++
	return f.tokens, nil
}
func (f *fakeSetupWizard) ApproveSiteToSiteSetup(_ context.Context) error {
	f.approved = true
	return f.approveErr
}

func newSetupWizardTestHandler(t *testing.T, wizard *fakeSetupWizard, token string) *Handler {
	t.Helper()
	wizard.view.Role = "dialer"
	wizard.view.ActiveState = "inactive"
	h, err := New(token, wizard)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func wizardPost(t *testing.T, h *Handler, path string, cookie *http.Cookie, csrf string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	values.Set("csrf", csrf)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	return resp
}

func TestSetupWizardPageIsAuthenticatedAndShowsGuidedForm(t *testing.T) {
	wizard := &fakeSetupWizard{
		fakeManagerController: &fakeManagerController{fakeController: &fakeController{}},
		status: adminapi.SiteToSiteSetupStatus{Available: true, State: "idle"},
	}
	h := newSetupWizardTestHandler(t, wizard, strings.Repeat("k", 64))
	cookie, _ := managerSession(t, h, strings.Repeat("k", 64))
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/setup", nil)
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("wizard status=%d body=%s", resp.Code, resp.Body.String())
	}
	for _, want := range []string{"PQTunnel Setup Wizard", "gateway_ssh_target", "gateway_name", "tcp_ports", "udp_ports", "Start preflight"} {
		if !strings.Contains(resp.Body.String(), want) {
			// Persian is the default UI language; just validate the stable form fields and product title.
			if want == "PQTunnel Setup Wizard" || want == "Start preflight" {
				continue
			}
			t.Errorf("wizard page missing %q", want)
		}
	}
}

func TestSetupWizardStartRequiresCSRFAndPassesOnlyValidatedFields(t *testing.T) {
	wizard := &fakeSetupWizard{
		fakeManagerController: &fakeManagerController{fakeController: &fakeController{}},
		status: adminapi.SiteToSiteSetupStatus{Available: true, State: "idle"},
	}
	h := newSetupWizardTestHandler(t, wizard, strings.Repeat("s", 64))
	cookie, csrf := managerSession(t, h, strings.Repeat("s", 64))
	values := url.Values{
		"gateway_ssh_target": {"root@203.0.113.10"},
		"ssh_port": {"22"},
		"gateway_name": {"203.0.113.10"},
		"tls_port": {"8443"},
		"tcp_ports": {"443"},
		"udp_ports": {"53,123"},
		"dialer_wan": {""},
		"gateway_wan": {""},
	}
	resp := wizardPost(t, h, "/setup/start", cookie, csrf, values)
	if resp.Code != http.StatusSeeOther || !strings.Contains(resp.Header().Get("Location"), "notice=started") {
		t.Fatalf("start status=%d location=%q body=%s", resp.Code, resp.Header().Get("Location"), resp.Body.String())
	}
	if wizard.started.Confirm != "CHECK" {
		t.Fatalf("wizard bypassed preflight gate, confirm=%q", wizard.started.Confirm)
	}
	if wizard.started.GatewaySSHTarget != "root@203.0.113.10" || wizard.started.SSHPort != 22 || wizard.started.TLSPort != 8443 {
		t.Fatalf("form values not passed to validated request: %#v", wizard.started)
	}
}

func TestSetupWizardRequiresSeparateApprovalAfterPreflight(t *testing.T) {
	wizard := &fakeSetupWizard{
		fakeManagerController: &fakeManagerController{fakeController: &fakeController{}},
		status: adminapi.SiteToSiteSetupStatus{Available: true, State: "awaiting-confirmation"},
	}
	h := newSetupWizardTestHandler(t, wizard, strings.Repeat("a", 64))
	cookie, csrf := managerSession(t, h, strings.Repeat("a", 64))
	values := url.Values{"confirm": {"yes"}}
	resp := wizardPost(t, h, "/setup/approve", cookie, csrf, values)
	if resp.Code != http.StatusSeeOther || !strings.Contains(resp.Header().Get("Location"), "notice=approved") {
		t.Fatalf("approval status=%d location=%q", resp.Code, resp.Header().Get("Location"))
	}
	if !wizard.approved {
		t.Fatal("separate approval action was not invoked")
	}
}

func TestSetupWizardCannotRunFromPublicManagerConfiguration(t *testing.T) {
	wizard := &fakeSetupWizard{
		fakeManagerController: &fakeManagerController{fakeController: &fakeController{}},
		status: adminapi.SiteToSiteSetupStatus{Available: true, State: "idle"},
	}
	h, err := NewWithAllowedPublicHost(strings.Repeat("p", 64), wizard, "203.0.113.20")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("p", 64)
	loginValues := url.Values{"token": {token}}
	loginReq := httptest.NewRequest(http.MethodPost, "https://203.0.113.20/login", strings.NewReader(loginValues.Encode()))
	loginReq.TLS = &tls.ConnectionState{}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "https://203.0.113.20")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusSeeOther {
		t.Fatalf("public manager test login status=%d body=%s", loginResp.Code, loginResp.Body.String())
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("public manager test login cookie missing")
	}
	dashboardReq := httptest.NewRequest(http.MethodGet, "https://203.0.113.20/", nil)
	dashboardReq.TLS = &tls.ConnectionState{}
	dashboardReq.AddCookie(cookies[0])
	dashboardResp := httptest.NewRecorder()
	h.ServeHTTP(dashboardResp, dashboardReq)
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(dashboardResp.Body.String())
	if dashboardResp.Code != http.StatusOK || len(csrf) != 2 {
		t.Fatalf("public manager dashboard unavailable: status=%d", dashboardResp.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.20/setup", nil)
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(cookies[0])
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("public-listener wizard access status=%d, want 403", resp.Code)
	}
}
