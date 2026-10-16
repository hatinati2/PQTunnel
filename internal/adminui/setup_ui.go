package adminui

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

var setupWizardTemplate = template.Must(template.New("setup-wizard").Funcs(template.FuncMap{
	"tr": translateText, "dir": languageDirection,
}).Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{dir .Lang}}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{{tr .Lang "راه‌اندازی گرافیکی PQTunnel" "PQTunnel Setup Wizard"}}</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--good:#86efac;--bad:#fca5a5;--warn:#fcd34d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#162641,#0b1020 55%);color:var(--text);font:15px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{width:min(1000px,calc(100% - 30px));margin:26px auto 60px}
header,.row{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}h1{font-size:1.65rem;margin:0}h2{font-size:1.1rem;margin:0 0 12px}.muted{color:var(--muted)}.links{display:flex;gap:9px;flex-wrap:wrap}.links a,button{display:inline-block;font:inherit;font-weight:700;border-radius:10px;padding:9px 13px;border:1px solid var(--line);background:#1b2940;color:var(--text);text-decoration:none;cursor:pointer}.panel{margin-top:17px;padding:20px;border:1px solid var(--line);border-radius:17px;background:linear-gradient(145deg,#162138,#11192b)}.alert{padding:12px 14px;border:1px solid #5b4b27;border-radius:11px;background:#292313;color:#fde68a;margin:14px 0}.error{border-color:#783b48;background:#351c2a;color:#fecaca}.success{border-color:#24533f;background:#10291f;color:#bbf7d0}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.field label{display:block;font-weight:700;margin-bottom:5px}.field input{width:100%;padding:11px 12px;background:#0c1425;color:var(--text);border:1px solid #394966;border-radius:10px;font:inherit}.hint{display:block;font-size:.86rem;color:var(--muted);margin-top:4px}.buttonrow{margin-top:18px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}.primary{background:var(--accent);color:#092033;border-color:var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:480px;overflow:auto;background:#0a1221;padding:14px;border:1px solid #26334d;border-radius:12px;direction:ltr;text-align:left;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.step{display:inline-block;border:1px solid #34445e;border-radius:999px;padding:3px 10px;color:var(--muted);font-size:.85rem}.tokens{display:grid;gap:12px}.token{padding:12px;background:#0a1221;border:1px solid #26334d;border-radius:10px;overflow-wrap:anywhere;direction:ltr;text-align:left}.token b{display:block;color:var(--muted);font-size:.84rem;margin-bottom:4px}
@media(max-width:650px){.grid{grid-template-columns:1fr}.panel{padding:14px}.wrap{margin-top:18px}}
</style></head>
<body><main class="wrap">
<header><div><h1>{{tr .Lang "راه‌اندازی گرافیکی PQTunnel" "PQTunnel Setup Wizard"}}</h1><div class="muted">{{tr .Lang "نصب کنترل‌شدهٔ دو سرور از طریق پنل ایران (Dialer)" "Guided two-server setup from the Iran/Dialer panel"}}</div></div>
<nav class="links"><a href="/language?lang=fa&amp;next=/setup">فارسی</a><a href="/language?lang=en&amp;next=/setup">English</a><a href="/">{{tr .Lang "بازگشت به داشبورد" "Back to dashboard"}}</a></nav></header>
{{if .Notice}}<div class="alert {{if .IsError}}error{{end}}" role="status">{{.Notice}}{{if .Detail}} — {{.Detail}}{{end}}</div>{{end}}
<section class="panel"><div class="row"><h2>{{tr .Lang "وضعیت راه‌اندازی" "Setup status"}}</h2><span class="step">{{.Status.State}}</span></div>
{{if not .Status.Available}}
<div class="alert error">{{tr .Lang "موتور نصب گرافیکی در این نسخه نصب نیست. این صفحه فقط پس از انتشار و نصب نسخه‌ای که setup worker را دارد فعال می‌شود؛ از اجرای فرم روی نسخهٔ قدیمی خودداری کن." "The graphical setup worker is not installed in this version. This page becomes available after installing a release that includes the setup worker. Do not submit the form from an older release."}}</div>
{{else if eq .Status.State "idle"}}
<p class="muted">{{tr .Lang "این مرحله با SSH کلیدمحور به آلمان وصل می‌شود، بسته‌ها را بررسی و فایل‌های لازم را دریافت می‌کند. اگر ابزار پیش‌نیاز نصب نباشد، ممکن است بسته‌های سیستم‌عامل نصب شوند. پیکربندی تونل یا قوانین مسیر تا تأیید نهایی اعمال نمی‌شود." "This phase connects to Germany with key-based SSH, checks/downloads assets, and may install missing OS prerequisite packages. Tunnel configuration and route rules are not applied until final approval."}}</p>
{{else if eq .Status.State "running"}}
<div class="alert">{{tr .Lang "نصاب در حال اجراست. برای دیدن گزارش تازه، دکمهٔ به‌روزرسانی وضعیت را بزن. پس از بررسی‌های هر دو سرور، این صفحه برنامهٔ نهایی را برای تأیید نمایش می‌دهد." "Setup is running. Refresh to load recent output. After checks on both hosts, this page will present a final plan for approval."}}</div>
{{else if eq .Status.State "awaiting-confirmation"}}
<div class="alert error">{{tr .Lang "پیش‌بررسی تمام شده است. گزارش و رابط‌های شبکهٔ انتخاب‌شده را بررسی کن. تأیید بعدی گواهی‌ها، سرویس‌ها و قوانین مسیریابی را اعمال می‌کند و ممکن است SSH قطع شود." "Preflight has completed. Review the report and selected network interfaces. The next confirmation applies certificates, services, and routing rules and may interrupt SSH."}}</div>
{{else if eq .Status.State "succeeded"}}
<div class="alert success">{{tr .Lang "فرایند نصب با کد خروج موفق تمام شده است. وضعیت اتصال تونل را در داشبورد بررسی کن؛ پایان نصب به‌تنهایی تضمین نمی‌کند که peer واقعاً متصل باشد." "The installer exited successfully. Check tunnel connectivity on the dashboard; a successful exit alone does not prove that the peer is connected."}}</div>
{{else if eq .Status.State "failed"}}
<div class="alert error">{{tr .Lang "نصب متوقف شد یا شکست خورد. ممکن است بخشی از فایل‌ها یا سرویس‌ها ایجاد شده باشد. نصب را کورکورانه تکرار نکن؛ گزارش زیر را بررسی کن و پیش از تلاش مجدد وضعیت هر دو سرور را بازبینی کن." "Setup stopped or failed. Some files or services may have been created. Do not blindly retry; review the output and inspect both servers before another attempt."}}</div>
{{else if eq .Status.State "queued"}}
<div class="alert">{{tr .Lang "درخواست در صف شروع است." "Setup request is queued."}}</div>
{{end}}
{{if .Status.Output}}<h2>{{tr .Lang "گزارش آخرین اجرا (با حذف توکن‌ها)" "Latest run output (tokens redacted)"}}</h2><pre>{{.Status.Output}}</pre>{{end}}
<div class="buttonrow"><a href="/setup" class="links">{{tr .Lang "به‌روزرسانی وضعیت" "Refresh status"}}</a>
{{if eq .Status.State "awaiting-confirmation"}}<form method="post" action="/setup/approve"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="confirm" value="yes"><button class="primary" type="submit">{{tr .Lang "تأیید برنامه و اعمال تغییرات شبکه" "Approve plan and apply network changes"}}</button></form>{{end}}
{{if .Status.TokensAvailable}}<form method="post" action="/setup/tokens"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="confirm" value="yes"><button class="primary" type="submit">{{tr .Lang "نمایش یک‌بارهٔ توکن‌های جدید" "Show new tokens once"}}</button></form>{{end}}</div>
</section>
{{if and .Status.Available (eq .Status.State "idle")}}
<section class="panel"><h2>{{tr .Lang "۱. اتصال و تنظیمات دو سرور" "1. Server connection and tunnel settings"}}</h2>
<p class="muted">{{tr .Lang "ورود SSH با کلید برای کاربر root روی Gateway آلمان باید از قبل کار کند. رمز عبور SSH از طریق وب پذیرفته نمی‌شود. پورت پنل‌ها روی loopback می‌ماند و فایروال ارائه‌دهنده خودکار تغییر نمی‌کند." "Root key-based SSH access to the German Gateway must already work. SSH passwords are not accepted through the web form. Management panels remain loopback-only; cloud/provider firewalls are not changed automatically."}}</p>
<form method="post" action="/setup/start" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="grid">
<div class="field"><label for="gateway_ssh">{{tr .Lang "مقصد SSH سرور آلمان" "German Gateway SSH target"}}</label><input id="gateway_ssh" name="gateway_ssh_target" required maxlength="260" pattern="root@[A-Za-z0-9][A-Za-z0-9.-]*" placeholder="root@203.0.113.10"><small class="hint">{{tr .Lang "نمونه: root@203.0.113.10؛ این IP مستندسازی است و باید با آدرس واقعی جایگزین شود." "Example: root@203.0.113.10; this documentation address must be replaced with the real IP."}}</small></div>
<div class="field"><label for="ssh_port">{{tr .Lang "پورت SSH آلمان" "German SSH port"}}</label><input id="ssh_port" name="ssh_port" type="number" min="1" max="65535" value="22" required></div>
<div class="field"><label for="gateway_name">{{tr .Lang "IP یا نام دامنهٔ Gateway برای TLS" "Gateway IP or DNS name for TLS"}}</label><input id="gateway_name" name="gateway_name" required maxlength="253" placeholder="203.0.113.10"><small class="hint">{{tr .Lang "باید IP یا نامی باشد که کلاینت ایران واقعاً با آن به آلمان وصل می‌شود." "Must match the public endpoint used by the Iran Dialer."}}</small></div>
<div class="field"><label for="tls_port">{{tr .Lang "پورت شنوندهٔ تونل" "Tunnel listener port"}}</label><input id="tls_port" name="tls_port" type="number" min="1" max="65535" value="8443" required></div>
<div class="field"><label for="tcp_ports">{{tr .Lang "پورت‌های مقصد TCP از مسیر آلمان" "TCP destination ports through Germany"}}</label><input id="tcp_ports" name="tcp_ports" value="443" required pattern="([0-9]+(,[0-9]+)*)|none"><small class="hint">{{tr .Lang "مثل 443، 80,443 یا none؛ این تنظیم VPN تمام‌ترافیک نیست." "For example 443, 80,443, or none; this is not a full-tunnel VPN."}}</small></div>
<div class="field"><label for="udp_ports">{{tr .Lang "پورت‌های مقصد UDP از مسیر آلمان" "UDP destination ports through Germany"}}</label><input id="udp_ports" name="udp_ports" value="53,123" pattern="([0-9]+(,[0-9]+)*)|none"><small class="hint">{{tr .Lang "مثل 53,123 یا none" "For example 53,123 or none"}}</small></div>
<div class="field"><label for="dialer_wan">{{tr .Lang "رابط اینترنت ایران (اختیاری)" "Iran WAN interface (optional)"}}</label><input id="dialer_wan" name="dialer_wan" maxlength="15" placeholder="{{tr .Lang "تشخیص خودکار" "Auto-detect"}}"><small class="hint">{{tr .Lang "اگر خالی بماند، رابط مسیر پیش‌فرض انتخاب می‌شود." "Leave blank to use the detected default-route interface."}}</small></div>
<div class="field"><label for="gateway_wan">{{tr .Lang "رابط اینترنت آلمان (اختیاری)" "Germany WAN interface (optional)"}}</label><input id="gateway_wan" name="gateway_wan" maxlength="15" placeholder="{{tr .Lang "تشخیص خودکار" "Auto-detect"}}"><small class="hint">{{tr .Lang "اگر خالی بماند، رابط مسیر پیش‌فرض انتخاب می‌شود." "Leave blank to use the detected default-route interface."}}</small></div>
</div>
<div class="alert error">{{tr .Lang "هشدار: مرحلهٔ بررسی ممکن است بسته‌های پیش‌نیاز را نصب کند و در صورت نیاز پنل عمومی فعلی را امن‌سازی کند. پس از پیش‌بررسی، تأیید جداگانه لازم است؛ فقط وقتی کنسول اضطراری یا SSH مستقل از تونل داری، تغییر شبکه را تأیید کن. اگر UFW، قوانین فایروال/مسیر موجود یا endpoint قبلی پیدا شود، نصب باید متوقف شود." "Warning: preflight may install prerequisites and secure an existing public manager. A separate approval follows; approve network changes only when emergency console or SSH independent of the tunnel is available. Setup must stop if active UFW, existing firewall/routing rules, or an endpoint is detected."}}</div>
<div class="buttonrow"><button class="primary" type="submit">{{tr .Lang "شروع اتصال و بررسی دو سرور" "Connect and check both servers"}}</button><a href="/">{{tr .Lang "لغو و بازگشت" "Cancel and return"}}</a></div>
</form></section>
{{end}}
<footer class="muted">{{tr .Lang "PQTunnel آزمایشی است و ممیزی مستقل امنیتی نشده؛ برای استفادهٔ عملیاتی تأیید نشده است." "PQTunnel is experimental, has not had an independent security audit, and is not validated for production use."}}</footer>
</main></body></html>`))

var setupTokensTemplate = template.Must(template.New("setup-tokens").Funcs(template.FuncMap{
	"tr": translateText, "dir": languageDirection,
}).Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{dir .Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{tr .Lang "توکن‌های جدید PQTunnel" "New PQTunnel tokens"}}</title>
<style>:root{color-scheme:dark;--bg:#0b1020;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:var(--text);font:16px/1.7 system-ui,sans-serif;padding:20px}.wrap{max-width:850px;margin:35px auto}.panel{background:#141c2f;border:1px solid var(--line);border-radius:16px;padding:22px}.token{direction:ltr;text-align:left;overflow-wrap:anywhere;padding:12px;background:#080e19;border:1px solid #26334d;border-radius:9px;font-family:ui-monospace,monospace;margin:8px 0 17px}.muted{color:var(--muted)}a{color:var(--accent)}</style></head>
<body><main class="wrap"><section class="panel"><h1>{{tr .Lang "توکن‌های تازهٔ نصب" "New setup tokens"}}</h1><p>{{tr .Lang "این صفحه فقط یک بار نشان داده می‌شود. همین حالا هر مقدار را در یک محل امن ذخیره کن؛ توکن‌ها را در چت، گزارش‌ها یا مخزن قرار نده." "This page is shown only once. Save each value securely now; never paste tokens into chat, logs, or source control."}}</p>
{{if .Tokens.Dialer}}<b>{{tr .Lang "توکن پنل ایران (Dialer)" "Iran/Dialer panel token"}}</b><div class="token">{{.Tokens.Dialer}}</div>{{end}}
{{if .Tokens.Gateway}}<b>{{tr .Lang "توکن پنل آلمان (Gateway)" "Germany/Gateway panel token"}}</b><div class="token">{{.Tokens.Gateway}}</div>{{end}}
{{if .Tokens.SpeedTest}}<b>{{tr .Lang "توکن مشترک تست سرعت" "Shared speed-test token"}}</b><div class="token">{{.Tokens.SpeedTest}}</div>{{end}}
<p class="muted">{{tr .Lang "اگر نصب ناقص شده باشد، بخشی از سرویس‌ها ممکن است وجود داشته باشند؛ پیش از شروع مجدد وضعیت هر دو سرور را بررسی کن." "If setup failed part-way, some services may already exist; inspect both hosts before retrying."}}</p><p><a href="/setup">{{tr .Lang "بازگشت به وضعیت نصب" "Return to setup status"}}</a> · <a href="/">{{tr .Lang "داشبورد" "Dashboard"}}</a></p></section></main></body></html>`))

type setupPageData struct {
	CSRF string
	Lang string
	Status adminapi.SiteToSiteSetupStatus
	Notice string
	Detail string
	IsError bool
}

func (h *Handler) requireLoopbackSetupAccess(w http.ResponseWriter, r *http.Request) bool {
	if h.allowedPublicHost != "" || h.allowInsecurePublicHTTP {
		http.Error(w, translateText(requestLanguage(r), "راه‌اندازی دو سرور فقط از پنل خصوصی روی loopback مجاز است. ابتدا با SSH forwarding به پنل وصل شو؛ استفاده از این فرایند از پنل عمومی مسدود است.", "The two-server setup is allowed only from the private loopback panel. Connect using SSH forwarding first; launching this workflow from a public listener is blocked."), http.StatusForbidden)
		return false
	}
	return true
}

func (h *Handler) serveSetupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	_, current, ok := h.sessionFor(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !h.requireLoopbackSetupAccess(w, r) {
		return
	}
	if h.manager == nil || h.manager.ManagementSnapshot().Role != "dialer" {
		http.Error(w, translateText(requestLanguage(r), "راه‌اندازی دو سرور فقط از پنل ایران/Dialer در دسترس است.", "Two-server setup is available only from the Iran/Dialer panel."), http.StatusForbidden)
		return
	}
	wizard, ok := h.manager.(adminapi.SetupWizardController)
	if !ok {
		http.Error(w, translateText(requestLanguage(r), "این نسخه از مدیر وب، API راه‌اندازی گرافیکی را ندارد.", "This manager version does not include the graphical setup API."), http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := wizard.SiteToSiteSetupStatus(ctx)
	if err != nil {
		http.Error(w, translateText(requestLanguage(r), "خواندن وضعیت راه‌اندازی ممکن نشد.", "Could not read setup status."), http.StatusInternalServerError)
		return
	}
	noticeKey := r.URL.Query().Get("notice")
	lang := requestLanguage(r)
	notice := setupNotice(noticeKey, lang)
	detail := safeNoticeDetail(r.URL.Query().Get("detail"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := setupWizardTemplate.Execute(w, setupPageData{CSRF: current.CSRF, Lang: lang, Status: status, Notice: notice, Detail: detail, IsError: noticeKey == "failed"}); err != nil {
		return
	}
}

func setupNotice(key, lang string) string {
	switch key {
	case "started":
		return translateText(lang, "درخواست بررسی در صف اجرا قرار گرفت.", "Preflight request queued.")
	case "approved":
		return translateText(lang, "تأیید ثبت شد؛ نصب و اعمال تنظیمات آغاز می‌شود.", "Approval recorded; installation and network changes are starting.")
	case "failed":
		return translateText(lang, "شروع نصب موفق نبود.", "Setup could not be started.")
	case "tokens-consumed":
		return translateText(lang, "توکن‌ها یک‌بار مصرف شدند و دیگر از این مسیر قابل بازیابی نیستند.", "The one-time tokens were consumed and cannot be retrieved again through this page.")
	case "invalid":
		return translateText(lang, "اطلاعات فرم معتبر نبود.", "The form contained invalid values.")
	default:
		return ""
	}
}

func (h *Handler) startSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok {
		return
	}
	if !h.requireLoopbackSetupAccess(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
		http.Error(w, translateText(requestLanguage(r), "درخواست نامعتبر است.", "Invalid request."), http.StatusBadRequest)
		return
	}
	if h.manager == nil {
		http.Error(w, "setup management unavailable", http.StatusNotFound)
		return
	}
	wizard, ok := h.manager.(adminapi.SetupWizardController)
	if !ok {
		http.Error(w, translateText(requestLanguage(r), "نسخهٔ مدیر وب از راه‌اندازی گرافیکی پشتیبانی نمی‌کند.", "This manager version does not support graphical setup."), http.StatusNotImplemented)
		return
	}
	sshPort, err1 := strconv.Atoi(r.PostForm.Get("ssh_port"))
	tlsPort, err2 := strconv.Atoi(r.PostForm.Get("tls_port"))
	if err1 != nil || err2 != nil {
		http.Redirect(w, r, "/setup?notice=invalid", http.StatusSeeOther)
		return
	}
	req := adminapi.SiteToSiteSetupRequest{
		GatewaySSHTarget: strings.TrimSpace(r.PostForm.Get("gateway_ssh_target")),
		SSHPort: sshPort,
		GatewayName: strings.TrimSpace(r.PostForm.Get("gateway_name")),
		TLSPort: tlsPort,
		TCPPorts: strings.TrimSpace(r.PostForm.Get("tcp_ports")),
		UDPPorts: strings.TrimSpace(r.PostForm.Get("udp_ports")),
		DialerWAN: strings.TrimSpace(r.PostForm.Get("dialer_wan")),
		GatewayWAN: strings.TrimSpace(r.PostForm.Get("gateway_wan")),
		Confirm: "CHECK",
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := wizard.StartSiteToSiteSetup(ctx, req); err != nil {
		target := "/setup?notice=failed&detail=" + url.QueryEscape(err.Error())
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup?notice=started", http.StatusSeeOther)
}

func (h *Handler) approveSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok {
		return
	}
	if !h.requireLoopbackSetupAccess(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, translateText(requestLanguage(r), "درخواست یا تأیید نامعتبر است.", "Request or confirmation is invalid."), http.StatusBadRequest)
		return
	}
	if h.manager == nil || h.manager.ManagementSnapshot().Role != "dialer" {
		http.Error(w, translateText(requestLanguage(r), "تأیید نصب از این پنل مجاز نیست.", "Installation approval is not allowed from this panel."), http.StatusForbidden)
		return
	}
	wizard, ok := h.manager.(adminapi.SetupWizardController)
	if !ok {
		http.Error(w, translateText(requestLanguage(r), "نسخهٔ مدیر وب از راه‌اندازی گرافیکی پشتیبانی نمی‌کند.", "This manager version does not support graphical setup."), http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := wizard.ApproveSiteToSiteSetup(ctx); err != nil {
		http.Redirect(w, r, "/setup?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup?notice=approved", http.StatusSeeOther)
}

func (h *Handler) consumeSetupTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok {
		return
	}
	if !h.requireLoopbackSetupAccess(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, translateText(requestLanguage(r), "درخواست یا تأیید نامعتبر است.", "Request or confirmation is invalid."), http.StatusBadRequest)
		return
	}
	wizard, ok := h.manager.(adminapi.SetupWizardController)
	if !ok || h.manager.ManagementSnapshot().Role != "dialer" {
		http.Error(w, translateText(requestLanguage(r), "بازیابی توکن در این پنل در دسترس نیست.", "Token handoff is unavailable in this panel."), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tokens, err := wizard.ConsumeSiteToSiteSetupTokens(ctx)
	if err != nil {
		http.Redirect(w, r, "/setup?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	_ = setupTokensTemplate.Execute(w, struct {
		Lang string
		Tokens adminapi.SiteToSiteSetupTokens
	}{Lang: requestLanguage(r), Tokens: tokens})
}
