package adminui

import (
	"context"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const maxNodeProfileUpload = 1 << 20

var nodeSetupTemplate = template.Must(template.New("node-setup").Funcs(template.FuncMap{
	"tr": translateText, "dir": languageDirection,
}).Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{dir .Lang}}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{{tr .Lang "راه‌اندازی مستقل PQTunnel" "Standalone PQTunnel setup"}}</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--good:#86efac;--warn:#fcd34d;--bad:#fecaca}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#162641,#0b1020 55%);color:var(--text);font:15px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}
main{width:min(100%,960px);margin:22px auto 60px}.panel{border:1px solid var(--line);background:linear-gradient(145deg,#162138,#11192b);border-radius:17px;padding:22px;margin-bottom:16px}
h1{font-size:1.55rem;margin:0 0 6px}h2{font-size:1.1rem;margin:0 0 12px}.muted{color:var(--muted)}.links{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}.links a{color:var(--accent);text-decoration:none}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
label{display:block;font-weight:650}.field input{display:block;width:100%;margin-top:5px;padding:11px 12px;border:1px solid #394966;border-radius:10px;background:#0c1425;color:var(--text);font:inherit}
button,.download{display:inline-block;margin-top:16px;padding:10px 15px;border:1px solid var(--line);border-radius:10px;background:#1b2940;color:var(--text);font:inherit;font-weight:700;text-decoration:none;cursor:pointer}
.primary{background:var(--accent);color:#092033;border-color:var(--accent)}.notice{padding:12px 14px;border:1px solid #2d5162;background:#122938;border-radius:10px;margin:12px 0}.warn{padding:12px 14px;border:1px solid #765b26;background:#2a2414;border-radius:10px;margin:12px 0;color:#fde68a}
.status{font-weight:800}.state-ready{color:var(--good)}.state-failed{color:var(--bad)}.state-waiting-for-peer{color:var(--warn)}
input[type=file]{display:block;margin-top:10px;max-width:100%;font:inherit}pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:600px){.grid{grid-template-columns:1fr}.panel{padding:15px}}
</style></head>
<body><main>
<div class="links"><a href="/">{{tr .Lang "← بازگشت به پنل" "← Back to dashboard"}}</a><a href="/language?lang=fa&amp;next=/node-setup">فارسی</a><a href="/language?lang=en&amp;next=/node-setup">English</a></div>
<section class="panel">
<h1>{{tr .Lang "راه‌اندازی مستقل PQTunnel" "Standalone PQTunnel setup"}}</h1>
<p class="muted">{{tr .Lang "این سرور به‌تنهایی نصب و مدیریت می‌شود. سرویس تونل تا زمانی که خودت از داشبورد شروع نکنی فعال نمی‌شود." "This server is installed and managed independently. The tunnel stays stopped until you explicitly start it from the dashboard."}}</p>
<p>{{tr .Lang "نقش این سرور: " "This server role: "}}<b>{{if eq .Role "gateway"}}Gateway{{else}}Dialer{{end}}</b></p>
{{if .Notice}}<div class="notice">{{.Notice}}{{if .Detail}} — {{.Detail}}{{end}}</div>{{end}}
{{if not .Status.Available}}
<div class="warn">{{tr .Lang "ابزار راه‌اندازی مستقل روی این نسخه نصب نیست. بستهٔ node را نصب یا به‌روزرسانی کن؛ سرویس‌های دیگر تغییری نمی‌کنند." "The standalone node setup worker is not installed in this release. Install or upgrade the node package; other services are not changed."}}</div>
{{else}}
<p class="status {{if eq .Status.State "ready"}}state-ready{{else if eq .Status.State "failed"}}state-failed{{else if eq .Status.State "waiting-for-peer"}}state-waiting-for-peer{{end}}">{{tr .Lang "وضعیت راه‌اندازی: " "Setup state: "}}{{.Status.State}}</p>
{{if .Status.Output}}<pre class="muted">{{.Status.Output}}</pre>{{end}}
{{if .Status.BundleAvailable}}<a class="download" href="/node-setup/bundle">{{tr .Lang "دریافت پروفایل عمومی این سرور" "Download this server's public profile"}}</a>{{end}}
{{if eq .Role "gateway"}}
{{if not .Status.BundleAvailable}}
<section class="panel">
<h2>{{tr .Lang "۱. ساخت پروفایل Gateway" "1. Create Gateway profile"}}</h2>
<p class="muted">{{tr .Lang "نام دامنه یا IP باید همان آدرسی باشد که Dialer برای اتصال استفاده می‌کند. فقط گواهی و اطلاعات عمومی صادر می‌شود؛ کلیدهای خصوصی روی همین VPS می‌مانند." "Use the DNS name or IP the Dialer will connect to. Only the public CA profile is exported; private keys stay on this VPS."}}</p>
<form method="post" action="/node-setup/start">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="grid">
<div class="field"><label for="public_name">{{tr .Lang "نام دامنه یا IP عمومی" "Public DNS name or IP"}}<input id="public_name" name="public_name" required maxlength="253" placeholder="203.0.113.10"></label></div>
<div class="field"><label for="listen_port">{{tr .Lang "پورت TCP تونل" "Tunnel TCP port"}}<input id="listen_port" name="listen_port" type="number" min="1" max="65535" value="8443" required></label></div>
<div class="field"><label for="tcp_ports">{{tr .Lang "پورت‌های مقصد TCP" "TCP destination ports"}}<input id="tcp_ports" name="tcp_ports" value="443" required placeholder="443 or 80,443"></label></div>
<div class="field"><label for="udp_ports">{{tr .Lang "پورت‌های مقصد UDP" "UDP destination ports"}}<input id="udp_ports" name="udp_ports" value="53,123" required placeholder="53,123 or none"></label></div>
</div>
<div class="warn">{{tr .Lang "ساخت پروفایل تونل را اجرا نمی‌کند و قوانین شبکه را تغییر نمی‌دهد. پس از ساخت، پروفایل عمومی را روی Dialer وارد کن؛ سپس پروفایل عمومی Dialer را از این صفحه وارد کن." "Generating the profile does not start the tunnel or change network rules. Import this public profile on the Dialer, then import the Dialer's public profile here."}}</div>
<button class="primary" type="submit">{{tr .Lang "ساخت پروفایل Gateway" "Generate Gateway profile"}}</button>
</form>
</section>
{{else if ne .Status.State "ready"}}
<section class="panel">
<h2>{{tr .Lang "۲. واردکردن پروفایل عمومی Dialer" "2. Import Dialer public profile"}}</h2>
<p class="muted">{{tr .Lang "پروفایل Dialer شامل CA عمومی و هویت گواهی است؛ کلید خصوصی Dialer داخل فایل نیست." "The Dialer profile contains its public CA and certificate identity; it does not contain the Dialer's private key."}}</p>
<form method="post" action="/node-setup/import" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>{{tr .Lang "فایل پروفایل Dialer (.tar.gz)" "Dialer profile file (.tar.gz)"}}<input type="file" name="profile" accept=".gz,.tgz,.tar.gz,application/gzip" required></label>
<button class="primary" type="submit">{{tr .Lang "واردکردن پروفایل Dialer" "Import Dialer profile"}}</button>
</form>
</section>
{{end}}
{{else}}
{{if ne .Status.State "ready"}}
<section class="panel">
<h2>{{tr .Lang "واردکردن پروفایل Gateway" "Import Gateway profile"}}</h2>
<p class="muted">{{tr .Lang "ابتدا از پنل Gateway پروفایل عمومی دانلود کن و اینجا واردش کن. این عملیات کلید خصوصی کلاینت را همین‌جا روی Dialer می‌سازد؛ کلید خصوصی از طریق پروفایل منتقل نمی‌شود." "Download the public profile from the Gateway panel and upload it here. This creates the client private key locally on the Dialer; no private key is transferred in the profile."}}</p>
<form method="post" action="/node-setup/import" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>{{tr .Lang "فایل پروفایل Gateway (.tar.gz)" "Gateway profile file (.tar.gz)"}}<input type="file" name="profile" accept=".gz,.tgz,.tar.gz,application/gzip" required></label>
<button class="primary" type="submit">{{tr .Lang "واردکردن پروفایل و ساخت Dialer" "Import profile and configure Dialer"}}</button>
</form>
</section>
{{else}}
<p class="muted">{{tr .Lang "پیکربندی Dialer آماده است. پروفایل عمومی Dialer را به Gateway منتقل و آنجا وارد کن؛ سپس سرویس هر طرف را از داشبورد خودش شروع کن." "Dialer configuration is ready. Transfer the Dialer's public profile to the Gateway and import it there; then start each endpoint from its own dashboard."}}</p>
{{end}}
{{end}}
{{end}}
</section>
<section class="panel">
<h2>{{tr .Lang "توضیح مهم" "Important notes"}}</h2>
<ul>
<li>{{tr .Lang "کلیدهای خصوصی از این سرور خارج نمی‌شوند؛ فقط CA و فرادادهٔ عمومی صادر می‌شود." "Private keys never leave this server; only public CA certificates and endpoint metadata are exported."}}</li>
<li>{{tr .Lang "این مرحله فقط اتصال تونل و رابط TUN را آماده می‌کند؛ مسیر پیش‌فرض، فایروال، NAT و forwarding سیستم را تغییر نمی‌دهد." "This step prepares the tunnel connection and TUN interface only; it does not change the system default route, firewall, NAT, or forwarding."}}</li>
<li>{{tr .Lang "پروفایل‌های عمومی از طریق HTTP قابل جعل هستند؛ برای تست از محیط مورد اعتماد استفاده کن و پیش از استفاده حساس، HTTPS را فعال و اثرانگشت گواهی‌ها را خارج از همین مسیر تأیید کن." "Public profiles can be tampered with over HTTP. Use a trusted environment for testing; before sensitive use, enable HTTPS and verify certificate fingerprints out-of-band."}}</li>
</ul>
</section>
{{end}}
</main></body></html>`))

type nodeSetupPageData struct {
	CSRF string
	Lang string
	Role string
	Status adminapi.NodeSetupStatus
	Notice string
	Detail string
}

func (h *Handler) serveNodeSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	_, current, ok := h.sessionFor(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if h.manager == nil {
		http.Error(w, translateText(requestLanguage(r), "مدیریت در این پنل در دسترس نیست.", "Management is unavailable in this panel."), http.StatusNotFound)
		return
	}
	setup, ok := h.manager.(adminapi.NodeSetupController)
	if !ok {
		http.Error(w, translateText(requestLanguage(r), "نسخهٔ پنل از راه‌اندازی مستقل پشتیبانی نمی‌کند.", "This manager does not support standalone setup."), http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := setup.NodeSetupStatus(ctx)
	if err != nil {
		http.Error(w, translateText(requestLanguage(r), "خواندن وضعیت راه‌اندازی ناموفق بود.", "Could not read setup status."), http.StatusInternalServerError)
		return
	}
	lang := requestLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := nodeSetupTemplate.Execute(w, nodeSetupPageData{
		CSRF: current.CSRF, Lang: lang, Role: h.manager.ManagementSnapshot().Role,
		Status: status, Notice: nodeSetupNotice(r.URL.Query().Get("notice"), lang),
		Detail: safeNoticeDetail(r.URL.Query().Get("detail")),
	}); err != nil {
		return
	}
}

func nodeSetupNotice(key, lang string) string {
	switch key {
	case "started":
		return translateText(lang, "درخواست راه‌اندازی ثبت شد.", "Setup request queued.")
	case "uploaded":
		return translateText(lang, "پروفایل عمومی بارگذاری شد.", "Public profile uploaded.")
	case "failed":
		return translateText(lang, "عملیات راه‌اندازی ناموفق بود.", "Setup operation failed.")
	default:
		return ""
	}
}

func (h *Handler) startNodeSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok {
		return
	}
	if h.manager == nil {
		http.Error(w, "setup manager unavailable", http.StatusNotFound)
		return
	}
	setup, ok := h.manager.(adminapi.NodeSetupController)
	if !ok {
		http.Error(w, "standalone setup is unavailable in this manager version", http.StatusNotImplemented)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
		http.Error(w, translateText(requestLanguage(r), "درخواست نامعتبر است.", "Invalid request."), http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(r.PostForm.Get("listen_port"))
	if err != nil {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape("Invalid listener port"), http.StatusSeeOther)
		return
	}
	req := adminapi.NodeSetupRequest{
		Operation: "gateway-init",
		PublicName: strings.TrimSpace(r.PostForm.Get("public_name")),
		ListenPort: port,
		TCPPorts: strings.TrimSpace(r.PostForm.Get("tcp_ports")),
		UDPPorts: strings.TrimSpace(r.PostForm.Get("udp_ports")),
	}
	if err := setup.StartNodeSetup(r.Context(), req); err != nil {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/node-setup?notice=started", http.StatusSeeOther)
}

func (h *Handler) importNodeSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok {
		return
	}
	if h.manager == nil {
		http.Error(w, "setup manager unavailable", http.StatusNotFound)
		return
	}
	setup, ok := h.manager.(adminapi.NodeSetupController)
	if !ok {
		http.Error(w, "standalone setup is unavailable in this manager version", http.StatusNotImplemented)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxNodeProfileUpload+64*1024)
	if err := r.ParseMultipartForm(256 * 1024); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
		http.Error(w, translateText(requestLanguage(r), "درخواست یا فایل نامعتبر است.", "Invalid request or profile upload."), http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("profile")
	if err != nil {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape("Select a public profile bundle"), http.StatusSeeOther)
		return
	}
	defer file.Close()
	if header.Size < 2 || header.Size > maxNodeProfileUpload {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape("Profile bundle must be smaller than 1 MiB"), http.StatusSeeOther)
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxNodeProfileUpload+1))
	if err != nil || len(data) > maxNodeProfileUpload {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape("Could not read profile bundle"), http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := setup.UploadNodeSetupBundle(ctx, data); err != nil {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	role := h.manager.ManagementSnapshot().Role
	operation := ""
	switch role {
	case "dialer":
		operation = "dialer-import-gateway"
	case "gateway":
		operation = "gateway-import-dialer"
	default:
		http.Error(w, errors.New("manager role is invalid").Error(), http.StatusInternalServerError)
		return
	}
	req := adminapi.NodeSetupRequest{Operation: operation}
	if err := setup.StartNodeSetup(ctx, req); err != nil {
		http.Redirect(w, r, "/node-setup?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/node-setup?notice=started", http.StatusSeeOther)
}

func (h *Handler) downloadNodeSetupBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	_, _, ok := h.sessionFor(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if h.manager == nil {
		http.Error(w, "setup manager unavailable", http.StatusNotFound)
		return
	}
	setup, ok := h.manager.(adminapi.NodeSetupController)
	if !ok {
		http.Error(w, "standalone setup is unavailable in this manager version", http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	data, err := setup.ReadNodeSetupBundle(ctx)
	if err != nil {
		http.Error(w, translateText(requestLanguage(r), "پروفایل عمومی آماده نیست.", "Public profile is not available."), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"pqtunnel-node-profile.tar.gz\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
