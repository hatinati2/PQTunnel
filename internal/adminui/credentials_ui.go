package adminui

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type credentialManager interface {
	GenerateGatewayCredentials(ctx context.Context, serverName string) error
	ExportDialerBundle() ([]byte, error)
	ImportDialerBundle(ctx context.Context, data []byte) error
}

type credentialsPageData struct {
	CSRF            string
	Lang            string
	Role            string
	Ready           bool
	Message         string
	BundleAvailable bool
	Notice          string
	Detail          string
}

var credentialsTemplate = template.Must(template.New("credentials").Funcs(template.FuncMap{
	"tr": translateText, "dir": languageDirection,
}).Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{dir .Lang}}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{{tr .Lang "گواهی‌های تونل PQTunnel" "PQTunnel Tunnel Credentials"}}</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--warn:#fcd34d;--danger:#fecaca}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#162641,#0b1020 55%);color:var(--text);font:16px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}
main{width:min(100%,850px);margin:28px auto}.panel{border:1px solid var(--line);background:linear-gradient(145deg,#162138,#11192b);border-radius:17px;padding:22px;margin:14px 0}
h1{font-size:1.5rem;margin:0 0 7px}h2{font-size:1.1rem;margin:0 0 10px}.muted{color:var(--muted)}.warn{border:1px solid #785b24;background:#302713;color:#ffedb0;padding:12px 14px;border-radius:12px;margin:12px 0}
.status{padding:12px;border:1px solid var(--line);border-radius:10px;margin:12px 0;overflow-wrap:anywhere}
label{display:block;font-weight:650;margin:12px 0 7px}input[type=text],input[type=file]{display:block;width:100%;margin-top:6px;padding:11px 12px;border:1px solid #394966;border-radius:10px;background:#0c1425;color:var(--text);font:inherit}
button,.link{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:#1b2940;color:var(--text);font:inherit;font-weight:700;text-decoration:none;cursor:pointer}
button.primary{background:var(--accent);color:#092033;border:0}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:15px}a{color:var(--accent)}
</style></head>
<body><main>
<header><h1>{{tr .Lang "اعتبارنامه‌های تونل" "Tunnel credentials"}}</h1><p class="muted">{{tr .Lang "اینجا فقط اعتبارنامه‌های endpoint این سرور آماده می‌شود. سرویس تونل تا زمانی که خودت آن را شروع نکنی فعال نمی‌شود." "Prepare credentials for this server's endpoint here. The tunnel service remains stopped until you explicitly start it."}}</p></header>
<div class="warn">{{tr .Lang "هشدار امنیتی: HTTP رمزنگاری ندارد. بستهٔ Dialer شامل کلید خصوصی است؛ دانلود یا بارگذاری آن از طریق HTTP می‌تواند کلید را در معرض شنود قرار دهد. فقط برای آزمایش موقت استفاده کن و پیش از استفادهٔ واقعی HTTPS را فعال کن." "Security warning: HTTP is not encrypted. The Dialer bundle contains a private key; downloading or uploading it over HTTP exposes that key to interception. Use this only for temporary testing and enable HTTPS before real use."}}</div>
{{if .Notice}}<div class="status">{{.Notice}}{{if .Detail}} — {{.Detail}}{{end}}</div>{{end}}
<section class="panel"><h2>{{tr .Lang "وضعیت اعتبارنامه" "Credential status"}}</h2>
<div class="status">{{if .Ready}}{{tr .Lang "اعتبارنامه‌ها نصب و اعتبارسنجی شده‌اند." "Credentials are installed and validated."}}{{else}}{{tr .Lang "اعتبارنامه‌ها هنوز آماده نیستند." "Credentials are not ready yet."}}{{end}}<p class="muted">{{.Message}}</p></div>
{{if eq .Role "gateway"}}
<h2>{{tr .Lang "ساخت اعتبارنامهٔ Gateway" "Generate Gateway credentials"}}</h2>
<p class="muted">{{tr .Lang "نام IP یا DNS باید همان نشانی‌ای باشد که Dialer برای بررسی گواهی TLS استفاده می‌کند. یک CA موقت، گواهی سرور و هویت peer برای Dialer ساخته می‌شود؛ کلید CA در پایان از workspace موقت حذف می‌شود." "Use the public IP or DNS name that the Dialer will verify for TLS. This creates a CA, server certificate, and a Dialer peer identity; the CA private key is deleted with the temporary workspace."}}</p>
<form method="post" action="/credentials/generate" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="server_name">{{tr .Lang "نام IP یا دامنهٔ Gateway" "Gateway IP or DNS identity"}}</label>
<input type="text" id="server_name" name="server_name" maxlength="253" required placeholder="vpn.example.net">
<input type="hidden" name="confirm" value="yes">
<div class="actions"><button class="primary" type="submit">{{tr .Lang "ساخت اعتبارنامه و بستهٔ Dialer" "Generate credentials and Dialer bundle"}}</button></div>
</form>
{{if .BundleAvailable}}
<div class="status">{{tr .Lang "بستهٔ Dialer آماده است. آن را دانلود کن و سپس در پنل Dialer بارگذاری کن." "The Dialer bundle is ready. Download it and upload it in the Dialer panel."}}</div>
<div class="actions"><a class="link" href="/credentials/export">{{tr .Lang "دانلود بستهٔ Dialer" "Download Dialer bundle"}}</a></div>
{{end}}
{{else}}
<h2>{{tr .Lang "وارد کردن بستهٔ Gateway" "Import Gateway bundle"}}</h2>
<p class="muted">{{tr .Lang "در پنل Gateway ابتدا اعتبارنامه‌ها را بساز و بسته را دانلود کن. سپس فایل ZIP را اینجا بارگذاری کن. نام TLS از بسته خوانده می‌شود و نشانی مقصد اولیه روی پورت 8443 تنظیم می‌شود؛ در صورت نیاز آن را در فرم تنظیمات تونل تغییر بده." "First generate credentials on the Gateway panel and download its bundle. Upload the ZIP here. The TLS name is read from the bundle and the initial destination uses port 8443; change the endpoint in the tunnel settings form if needed."}}</p>
<form method="post" action="/credentials/import" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="bundle">{{tr .Lang "فایل ZIP اعتبارنامهٔ Gateway" "Gateway credential ZIP"}}</label>
<input type="file" id="bundle" name="bundle" accept=".zip,application/zip" required>
<input type="hidden" name="confirm" value="yes">
<div class="actions"><button class="primary" type="submit">{{tr .Lang "اعتبارسنجی و نصب اعتبارنامه" "Validate and install credentials"}}</button></div>
</form>
{{end}}
<div class="actions"><a class="link" href="/">{{tr .Lang "بازگشت به داشبورد" "Back to dashboard"}}</a></div>
</section>
<footer class="muted">{{tr .Lang "این بخش گواهی و کلید TLS را آماده می‌کند؛ تنظیمات شبکه همچنان با کنترل‌های محافظت‌شده و پیش‌بررسی‌های اختصاصی اعمال می‌شوند." "This section prepares TLS credentials; network changes remain subject to protected controls and dedicated preflight checks."}}</footer>
</main></body></html>`))

func (h *Handler) serveCredentialsPage(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, translateText(requestLanguage(r), "مدیریت اعتبارنامه در دسترس نیست.", "Credential management is unavailable."), http.StatusNotFound)
		return
	}
	if _, ok := h.manager.(credentialManager); !ok {
		http.Error(w, translateText(requestLanguage(r), "این نسخه از مدیر وب قابلیت اعتبارنامه را ندارد.", "This manager version does not support credential provisioning."), http.StatusNotImplemented)
		return
	}
	view := h.manager.ManagementSnapshot()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = credentialsTemplate.Execute(w, credentialsPageData{
		CSRF: current.CSRF, Lang: requestLanguage(r), Role: view.Role,
		Ready: view.CredentialsReady, Message: view.CredentialMessage,
		BundleAvailable: view.PeerBundleAvailable,
		Notice: credentialsNotice(r.URL.Query().Get("notice"), requestLanguage(r)),
		Detail: safeNoticeDetail(r.URL.Query().Get("detail")),
	})
}

func credentialsNotice(key, lang string) string {
	switch key {
	case "generated":
		return translateText(lang, "اعتبارنامه‌ها ساخته شدند. بستهٔ Dialer را دانلود و به پنل Dialer منتقل کن.", "Credentials generated. Download the Dialer bundle and transfer it to the Dialer panel.")
	case "imported":
		return translateText(lang, "اعتبارنامه‌ها اعتبارسنجی و نصب شدند. تنظیمات تونل را بازبینی کن؛ سرویس هنوز شروع نشده است.", "Credentials validated and installed. Review tunnel settings; the service has not been started.")
	case "failed":
		return translateText(lang, "عملیات اعتبارنامه ناموفق بود.", "Credential operation failed.")
	default:
		return ""
	}
}

func (h *Handler) generateGatewayCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok { return }
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, translateText(requestLanguage(r), "درخواست یا تأیید نامعتبر است.", "Request or confirmation is invalid."), http.StatusBadRequest)
		return
	}
	credentials, ok := h.manager.(credentialManager)
	if !ok || h.manager == nil || h.manager.ManagementSnapshot().Role != "gateway" {
		http.Error(w, translateText(requestLanguage(r), "ساخت اعتبارنامه فقط از پنل Gateway مجاز است.", "Credential generation is available only on the Gateway panel."), http.StatusForbidden)
		return
	}
	serverName := strings.TrimSpace(r.PostForm.Get("server_name"))
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := credentials.GenerateGatewayCredentials(ctx, serverName); err != nil {
		http.Redirect(w, r, "/credentials?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/credentials?notice=generated", http.StatusSeeOther)
}

func (h *Handler) exportDialerBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	if _, _, ok := h.sessionFor(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	credentials, ok := h.manager.(credentialManager)
	if !ok || h.manager == nil || h.manager.ManagementSnapshot().Role != "gateway" {
		http.Error(w, translateText(requestLanguage(r), "بسته فقط از پنل Gateway قابل دانلود است.", "The bundle is downloadable only from the Gateway panel."), http.StatusForbidden)
		return
	}
	data, err := credentials.ExportDialerBundle()
	if err != nil {
		http.Error(w, translateText(requestLanguage(r), "بستهٔ Dialer آماده نیست.", "Dialer bundle is not ready."), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"pqtunnel-dialer-bundle.zip\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(data)
}

func (h *Handler) importDialerBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	_, current, ok := h.requirePostSession(w, r)
	if !ok { return }
	if h.manager == nil || h.manager.ManagementSnapshot().Role != "dialer" {
		http.Error(w, translateText(requestLanguage(r), "وارد کردن بسته فقط از پنل Dialer مجاز است.", "Bundle import is available only on the Dialer panel."), http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, (1<<20)+8192)
	if err := r.ParseMultipartForm(1 << 20); err != nil || !secureEqual(r.FormValue("csrf"), current.CSRF) || r.FormValue("confirm") != "yes" {
		http.Error(w, translateText(requestLanguage(r), "فرم بارگذاری نامعتبر است یا از حد مجاز بزرگ‌تر است.", "Upload form is invalid or exceeds the size limit."), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("bundle")
	if err != nil {
		http.Error(w, translateText(requestLanguage(r), "فایل ZIP اعتبارنامه پیدا نشد.", "Credential ZIP was not provided."), http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		http.Error(w, translateText(requestLanguage(r), "حجم بسته باید حداکثر یک مگابایت باشد.", "Bundle must be no larger than 1 MiB."), http.StatusBadRequest)
		return
	}
	credentials, ok := h.manager.(credentialManager)
	if !ok {
		http.Error(w, translateText(requestLanguage(r), "این نسخه از مدیر وب قابلیت وارد کردن اعتبارنامه را ندارد.", "This manager version cannot import credentials."), http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := credentials.ImportDialerBundle(ctx, data); err != nil {
		http.Redirect(w, r, "/credentials?notice=failed&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/credentials?notice=imported", http.StatusSeeOther)
}
