package adminui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
	"github.com/hatinati2/PQTunnel/internal/speedtest"
)

const (
	sessionCookieName = "pqtunnel_admin_session"
	sessionLifetime   = 12 * time.Hour
	maxSessions       = 128
	loginFailureLimit = 5
	loginWindow       = time.Minute
	maxLoginEntries   = 128
)

var (
	loginTemplate   = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ورود مدیریت PQTunnel</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--danger:#fecaca}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172742,#0b1020 65%);color:var(--text);font:16px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}
main{width:min(100%,430px);background:#141c2fee;border:1px solid var(--line);border-radius:22px;padding:30px;box-shadow:0 24px 80px #0005}
h1{font-size:1.5rem;margin:0 0 8px}.muted{color:var(--muted)}label{display:block;margin:18px 0 7px;font-weight:650}input{width:100%;padding:13px 14px;border-radius:11px;border:1px solid #394966;background:#0c1425;color:var(--text);font:inherit}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:11px;background:var(--accent);color:#092033;font:inherit;font-weight:750;cursor:pointer}.error{color:var(--danger);margin:12px 0 0}
</style></head>
<body><main><h1>مدیریت PQTunnel</h1><p class="muted">برای ورود، توکن مدیریتی تنظیم‌شده روی سرویس را وارد کنید.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/login" autocomplete="on">
<label for="token">توکن مدیریت</label><input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
<button type="submit">ورود امن</button></form>
</main></body></html>`))
	dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل مدیریت PQTunnel</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--panel2:#10182a;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--good:#86efac;--bad:#fca5a5;--warn:#fcd34d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#162641,#0b1020 55%);color:var(--text);font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{width:min(1100px,calc(100% - 32px));margin:34px auto 70px}
header{display:flex;gap:20px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:24px}
h1{font-size:1.7rem;margin:0}.sub{color:var(--muted);margin:5px 0 0}
button{font:inherit;font-weight:700;cursor:pointer;border-radius:10px;padding:9px 14px;border:1px solid var(--line);background:#1b2940;color:var(--text)}
button:hover{filter:brightness(1.15)}button.danger{border-color:#783b48;background:#351c2a;color:#fecaca}.logout{margin:0}
.header-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.refresh{display:inline-block;font:inherit;font-weight:700;text-decoration:none;border-radius:10px;padding:9px 14px;border:1px solid var(--line);background:#1b2940;color:var(--text)}
.disconnect summary{display:inline-block;cursor:pointer;font-weight:700;border-radius:10px;padding:8px 11px;border:1px solid #783b48;background:#351c2a;color:#fecaca;list-style:none}.disconnect summary::-webkit-details-marker{display:none}.disconnect[open] .peerform{margin-top:9px}.disconnect .danger{white-space:nowrap}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:16px}
.card,.section{border:1px solid var(--line);background:linear-gradient(145deg,#162138,#11192b);border-radius:17px;padding:19px;min-width:0}
.kicker{font-size:.82rem;color:var(--muted)}.metric{font-size:1.35rem;font-weight:800;overflow-wrap:anywhere;margin-top:5px}
.section{margin-top:16px}.section h2{font-size:1.1rem;margin:0 0 13px}
.details{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.detail{padding:13px;background:#0e1728;border:1px solid #22304a;border-radius:12px;min-width:0}.detail b{display:block;overflow-wrap:anywhere}
.status{display:inline-flex;align-items:center;gap:8px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--bad)}.dot.up{background:var(--good);box-shadow:0 0 14px #86efac66}
.notice{padding:12px 15px;margin:0 0 14px;border-radius:12px;border:1px solid #2d5162;background:#122938;color:#bae6fd}
.empty{padding:20px;border:1px dashed #35435d;border-radius:12px;color:var(--muted);text-align:center}
table{width:100%;border-collapse:collapse}th,td{text-align:right;padding:13px 10px;border-bottom:1px solid #26334d}th{color:var(--muted);font-size:.84rem;font-weight:650}tr:last-child td{border-bottom:0}.identity{font-weight:750;overflow-wrap:anywhere}.peerform{margin:0}
footer{color:var(--muted);font-size:.84rem;margin-top:18px}
@media(max-width:800px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.details{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:540px){.wrap{margin-top:22px}.grid,.details{grid-template-columns:1fr}.section{padding:14px}table,tbody,tr,td{display:block}thead{display:none}tr{border-bottom:1px solid #26334d;padding:9px 0}td{border:0;padding:5px 2px}td:before{content:attr(data-label) ": ";color:var(--muted)}td:last-child:before{content:""}}
 .configform{display:grid;gap:12px}.configform label{display:block;font-weight:650;margin:5px 0}.configform input:not([type=hidden]){display:block;width:100%;margin-top:6px;padding:11px 12px;border:1px solid #394966;border-radius:10px;background:#0c1425;color:var(--text);font:inherit}.configform input[type=number]{max-width:220px}.configform details{width:max-content;max-width:100%}.configform details p{max-width:700px}
</style></head>
<body><main class="wrap">
<header><div><h1>پنل مدیریت PQTunnel</h1><p class="sub">وضعیت سرویس و همتایان متصل · کنترل محدود و امن</p></div>
<div class="header-actions">{{if .Manager}}<a class="refresh" href="/logs">لاگ سرویس</a>{{end}}<a class="refresh" href="/">به‌روزرسانی وضعیت</a>
<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">خروج از پنل</button></form></div></header>
{{if .Notice}}<div class="notice" role="status">{{.Notice}}{{if .Detail}} — {{.Detail}}{{end}}</div>{{end}}
<section class="grid" aria-label="خلاصه وضعیت">
<div class="card"><div class="kicker">وضعیت سرویس</div><div class="metric status"><span class="dot {{if .Snapshot.Running}}up{{end}}"></span>{{if .Snapshot.Running}}فعال{{else}}متوقف / در حال راه‌اندازی{{end}}</div></div>
<div class="card"><div class="kicker">وضعیت اتصال تونل</div><div class="metric status"><span class="dot {{if .Snapshot.TransportConnected}}up{{end}}"></span>{{if not .Snapshot.Running}}سرویس متوقف{{else if .Manager}}{{if .Manager.PeerDataReady}}{{if .Manager.TransportConnected}}متصل{{else}}قطع / در انتظار اتصال{{end}}{{else}}نامشخص؛ control socket در دسترس نیست{{end}}{{else}}{{if .Snapshot.TransportConnected}}متصل{{else}}قطع / در انتظار اتصال{{end}}{{end}}</div></div>
<div class="card"><div class="kicker">همتایان متصل</div><div class="metric">{{if .Manager}}{{if .Manager.PeerDataReady}}{{len .Snapshot.Peers}} / {{.Snapshot.MaxClients}}{{else}}نامشخص{{end}}{{else}}{{len .Snapshot.Peers}} / {{.Snapshot.MaxClients}}{{end}}</div></div>
<div class="card"><div class="kicker">مدت اجرای جاری</div><div class="metric">{{if .Snapshot.Uptime}}{{.Snapshot.Uptime}}{{else}}—{{end}}</div></div>
<div class="card"><div class="kicker">حالت تونل</div><div class="metric">{{if .Snapshot.SiteToSite}}سایت‌به‌سایت{{else}}میزبان / کلاینت{{end}}</div></div>
</section>
<section class="section"><h2>پیکربندی مؤثر</h2><div class="details">
<div class="detail"><span class="kicker">نشانی شنونده</span><b>{{.Snapshot.ListenAddress}}</b></div>
<div class="detail"><span class="kicker">هویت همتای مورد انتظار</span><b>{{if .Snapshot.PeerIdentity}}{{.Snapshot.PeerIdentity}}{{else}}تنظیم نشده{{end}}</b></div>
<div class="detail"><span class="kicker">محدوده‌های مجاز</span><b>محلی: {{.Snapshot.LocalPrefixCount}} · همتا: {{.Snapshot.PeerPrefixCount}}</b></div>
</div></section>
{{if .Manager}}
<section class="section"><h2>کنترل سرویس تونل</h2>
<div class="details">
<div class="detail"><span class="kicker">نقش این سرور</span><b>{{if eq .Manager.Role "gateway"}}Gateway / Listener{{else}}Dialer{{end}}</b></div>
<div class="detail"><span class="kicker">واحد systemd</span><b>{{.Manager.ServiceUnit}}</b></div>
<div class="detail"><span class="kicker">وضعیت systemd</span><b>{{.Manager.ActiveState}} / {{.Manager.SubState}} · PID {{if .Manager.MainPID}}{{.Manager.MainPID}}{{else}}—{{end}}</b></div>
</div>
<p class="sub">استارت/استاپ/ری‌استارت اتصال فعال را قطع می‌کند. این عملیات فقط واحد ثابتِ نقش انتخاب‌شده را کنترل می‌کند؛ برای اعمال تغییر روی سرور عملیاتی، ابتدا مسیر بازیابی خارج از تونل را آماده کن.</p>
<div class="header-actions">
<details class="disconnect"><summary>Start</summary><form method="post" action="/service/action" class="peerform"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="start"><input type="hidden" name="confirm" value="yes"><button type="submit">تأیید راه‌اندازی</button></form></details>
<details class="disconnect"><summary>Stop</summary><form method="post" action="/service/action" class="peerform"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="stop"><input type="hidden" name="confirm" value="yes"><button class="danger" type="submit">تأیید توقف</button></form></details>
<details class="disconnect"><summary>Restart</summary><form method="post" action="/service/action" class="peerform"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="restart"><input type="hidden" name="confirm" value="yes"><button class="danger" type="submit">تأیید راه‌اندازی مجدد</button></form></details>
</div>
</section>
<section class="section"><h2>ویرایش تنظیمات تونل</h2>
{{if .Manager.ConfigError}}<div class="notice">{{.Manager.ConfigError}}</div>{{end}}
{{if .Manager.ConfigReady}}<p class="sub">آخرین تنظیمات خوانده‌شده از فایل سرویس. مسیر گواهی‌ها، کلیدها، توکن‌ها و متغیرهای مدیریتی از این فرم قابل تغییر نیستند.</p>{{else}}<p class="sub">فایل تنظیمات قابل خواندن نیست یا هنوز برای site-to-site کامل نشده است. مقادیر معتبر وارد کن؛ قبل از اعمال، اعتبارسنجی انجام می‌شود.</p>{{end}}
<form method="post" action="/config/apply" class="configform">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if eq .Manager.Role "gateway"}}
<label>نشانی شنونده (IP:port؛ برای چند نشانی با کاما جدا کن)<input name="listen_address" maxlength="512" required value="{{.Manager.Config.ListenAddress}}"></label>
<label>CIDRهای شبکهٔ سمت Dialer<input name="peer_prefixes" maxlength="2048" required value="{{.Manager.Config.PeerPrefixes}}"></label>
<label>CIDRهای مجاز سمت Gateway (از جمله IP تونل خود Gateway برای تست)<input name="local_prefixes" maxlength="2048" required value="{{.Manager.Config.LocalPrefixes}}"></label>
<label>Common Name گواهی peer<input name="peer_identity" maxlength="128" required value="{{.Manager.Config.PeerIdentity}}"></label>
{{else}}
<label>آدرس Listener با پورت (دامنه، IPv4 یا [IPv6])<input name="server_address" maxlength="512" required value="{{.Manager.Config.ServerAddress}}"></label>
<label>نام TLS که باید با SAN گواهی تطبیق داشته باشد<input name="server_name" maxlength="253" required value="{{.Manager.Config.ServerName}}"></label>
<label>CIDRهای محلی سمت Dialer<input name="local_prefixes" maxlength="2048" required value="{{.Manager.Config.LocalPrefixes}}"></label>
<label>CIDRهای سمت Gateway قابل‌دسترسی برای Dialer<input name="remote_prefixes" maxlength="2048" required value="{{.Manager.Config.RemotePrefixes}}"></label>
{{end}}
<label>Allowlist پورت‌های مقصد TCP/UDP<input name="allowed_dst_ports" maxlength="1024" required value="{{.Manager.Config.AllowedDstPorts}}"></label>
<p class="sub">تغییرات با اعتبارسنجی و تهیهٔ نسخهٔ پشتیبان ذخیره می‌شود. اگر سرویس فعال باشد، پنل آن را restart می‌کند؛ در صورت ناموفق‌بودن، تنظیم قبلی بازگردانده می‌شود. انتخاب default route یا CIDR هم‌پوشان رد می‌شود یا نیازمند بازبینی جداگانه است.</p>
<details class="disconnect"><summary>بررسی و اعمال تنظیمات</summary><p>اعمال ممکن است تونل را برای چند لحظه قطع کند. فقط وقتی دسترسی کنسول/SSH مستقل داری تأیید کن.</p><input type="hidden" name="confirm" value="yes"><button class="danger" type="submit">تأیید اعتبارسنجی و اعمال</button></details>
</form>
</section>
<section class="section"><h2>تست سرعت داخل تونل</h2>
{{if .Manager.SpeedTestReady}}
<p class="sub">مقصد ثابت و خصوصی: <b>{{.Manager.SpeedTestPeer}}</b>. اندازه‌گیری با RTT میانهٔ ۵ نمونه و انتقال داده در هر دو جهت از همین مسیر تونل انجام می‌شود. تست تا ۳۲ MiB داده تولید می‌کند و ممکن است پهنای باند را موقتاً اشغال کند.</p>
<form method="post" action="/speedtest/run" class="configform">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>حجم داده برای هر جهت (MiB)
<input type="number" name="megabytes" min="1" max="32" value="8" required>
</label>
<details class="disconnect"><summary>اجرای تست سرعت</summary><p>فقط یک تست هم‌زمان اجرا می‌شود؛ برای نتیجهٔ دقیق‌تر، انتقال‌های حجیم دیگر را متوقف کن.</p><input type="hidden" name="confirm" value="yes"><button type="submit">شروع تست دوطرفه</button></details></form>
{{else}}
<div class="empty">تست سرعت فعلاً غیرفعال است. روی هر دو سرور یک عامل speed test با IP خصوصی TUN و توکن مشترک تنظیم کن؛ نشانی مقصد این فرم قابل‌تغییر نیست و باید داخل prefixهای مجاز و allowlist پورت TCP باشد.</div>
{{end}}
{{if .Manager.LastSpeedTest}}
<h3>آخرین نتیجه</h3>
<div class="details">
<div class="detail"><span class="kicker">RTT میانه</span><b>{{printf "%.2f" .Manager.LastSpeedTest.RTTMillis}} ms</b></div>
<div class="detail"><span class="kicker">ارسال به سمت peer</span><b>{{printf "%.2f" .Manager.LastSpeedTest.UploadMbps}} Mbps</b></div>
<div class="detail"><span class="kicker">دریافت از peer</span><b>{{printf "%.2f" .Manager.LastSpeedTest.DownloadMbps}} Mbps</b></div>
<div class="detail"><span class="kicker">حجم هر جهت</span><b>{{.Manager.LastSpeedTest.SizeMiB}} MiB</b></div>
<div class="detail"><span class="kicker">زمان ارسال</span><b>{{printf "%.2f" .Manager.LastSpeedTest.UploadSeconds}} s</b></div>
<div class="detail"><span class="kicker">زمان دریافت</span><b>{{printf "%.2f" .Manager.LastSpeedTest.DownloadSeconds}} s</b></div>
</div>
<p class="sub">مقصد: {{.Manager.LastSpeedTest.Peer}} · زمان پایان: {{.Manager.LastSpeedTest.CompletedAt}}</p>
{{end}}
</section>
{{end}}
<section class="section"><h2>همتایان متصل</h2>
{{if .Snapshot.Peers}}<table><thead><tr><th>هویت گواهی</th><th>مدت اتصال</th><th>عملیات</th></tr></thead><tbody>
{{range .Snapshot.Peers}}<tr><td class="identity" data-label="هویت">{{.Identity}}</td><td data-label="مدت اتصال">{{.ConnectedFor}}</td><td><details class="disconnect"><summary>قطع اتصال</summary><form method="post" action="/peers/disconnect" class="peerform"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="identity" value="{{.Identity}}"><button class="danger" type="submit">تأیید قطع اتصال</button></form></details></td></tr>{{end}}
</tbody></table>{{else}}<div class="empty">در حال حاضر هیچ همتای احراز هویت‌شده‌ای متصل نیست.</div>{{end}}
</section>
<footer>{{if .Manager}}این پنل کنترل محدود سرویس، تنظیمات site-to-site و اتصال همتا را فراهم می‌کند. فایل‌های PKI، کلیدها، فایروال و قوانین NAT از این فرم تغییر نمی‌کنند. پنل باید فقط روی loopback در دسترس باشد.{{else}}این پنل فقط وضعیت را نمایش می‌دهد و اتصال همتا را قطع می‌کند؛ مسیرها، فایروال، NAT، گواهی‌ها و کلیدها را تغییر نمی‌دهد. پنل باید فقط روی loopback در دسترس باشد.{{end}}</footer>
</main></body></html>`))
	logsTemplate = template.Must(template.New("logs").Parse(`<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>لاگ سرویس PQTunnel</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--line:#26334d;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc}
*{box-sizing:border-box}body{margin:0;background:#0b1020;color:var(--text);font:14px/1.65 ui-monospace,monospace}.wrap{width:min(1200px,calc(100% - 28px));margin:24px auto}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}a{color:var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#10182a;border:1px solid var(--line);border-radius:12px;padding:16px;max-height:75vh;overflow:auto}
button{font:inherit;padding:8px 12px;background:#1b2940;color:var(--text);border:1px solid var(--line);border-radius:8px}
</style></head>
<body><main class="wrap"><header><div><h1>آخرین لاگ‌های سرویس {{.Unit}}</h1><p>حداکثر ۱۰۰ خط؛ مقادیر حساس شناخته‌شده حذف یا ماسک شده‌اند.</p></div>
<div><a href="/">بازگشت به پنل</a>
<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">خروج</button></form></div></header>
<pre>{{.Logs}}</pre></main></body></html>`))
)

type session struct {
	CSRF      string
	ExpiresAt time.Time
}

type loginAttempt struct {
	Failures     int
	WindowEnds   time.Time
	BlockedUntil time.Time
}

// Handler serves a token-protected local management UI with short-lived,
// in-memory sessions, login throttling, and CSRF protection for state changes.
type Handler struct {
	token         []byte
	controller    adminapi.Controller
	allowedPublicHost string
	manager       adminapi.ManagerController
	mu            sync.Mutex
	sessions           map[string]session
	loginAttempts      map[string]loginAttempt
	loginOverflowUntil time.Time
}

func New(token string, controller adminapi.Controller) (*Handler, error) {
	return NewWithAllowedPublicHost(token, controller, "")
}

// NewWithAllowedPublicHost permits a non-loopback HTTPS origin only when its
// literal public IP is explicitly configured. The HTTP listener itself enforces TLS.
func NewWithAllowedPublicHost(token string, controller adminapi.Controller, allowedPublicHost string) (*Handler, error) {
	if len([]byte(token)) < 32 {
		return nil, errors.New("admin token must contain at least 32 bytes")
	}
	if controller == nil {
		return nil, errors.New("admin controller is required")
	}
	if allowedPublicHost != "" {
		ip, err := netip.ParseAddr(allowedPublicHost)
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
			return nil, errors.New("allowed public host must be a public literal IP address")
		}
	}
	handler := &Handler{
		token: []byte(token), controller: controller, allowedPublicHost: allowedPublicHost,
		sessions: make(map[string]session), loginAttempts: make(map[string]loginAttempt),
	}
	if manager, ok := controller.(adminapi.ManagerController); ok {
		handler.manager = manager
	}
	return handler, nil
}

// ValidateLoopbackAddress forbids exposing the unencrypted admin HTTP server on
// a public or wildcard interface. Remote access should use an encrypted tunnel.
func ValidateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("admin listen address must be a literal loopback IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("admin panel may bind only to 127.0.0.1 or ::1")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("admin listen port must be between 1 and 65535")
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	switch r.URL.Path {
	case "/login":
		switch r.Method {
		case http.MethodGet:
			h.renderLogin(w, "")
		case http.MethodPost:
			h.login(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case "/":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		_, current, ok := h.sessionFor(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		var managerView *adminapi.ManagerSnapshot
		if h.manager != nil {
			view := h.manager.ManagementSnapshot()
			managerView = &view
		}
		data := struct {
			Snapshot adminapi.Snapshot
			CSRF     string
			Notice   string
			Detail   string
			Manager  *adminapi.ManagerSnapshot
		}{
			Snapshot: h.controller.AdminSnapshot(),
			CSRF:     current.CSRF,
			Notice:   noticeMessage(r.URL.Query().Get("notice")),
			Detail:   safeNoticeDetail(r.URL.Query().Get("detail")),
			Manager:  managerView,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dashboardTemplate.Execute(w, data); err != nil {
			return
		}
	case "/logs":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		_, current, ok := h.sessionFor(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if h.manager == nil {
			http.Error(w, "لاگ سرویس از این پنل در دسترس نیست.", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		logs, err := h.manager.RecentLogs(ctx)
		if err != nil {
			h.redirectWithDetail(w, r, "logs-failed", err.Error())
			return
		}
		view := h.manager.ManagementSnapshot()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := logsTemplate.Execute(w, struct {
			Unit string
			Logs string
			CSRF string
		}{Unit: view.ServiceUnit, Logs: logs, CSRF: current.CSRF}); err != nil {
			return
		}
	case "/speedtest/run":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		_, current, ok := h.requirePostSession(w, r)
		if !ok { return }
		if h.manager == nil {
			http.Error(w, "تست سرعت از این پنل در دسترس نیست.", http.StatusNotFound)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("confirm") != "yes" {
			http.Error(w, "تأیید اجرای تست سرعت الزامی است.", http.StatusBadRequest)
			return
		}
		sizeMiB, err := strconv.Atoi(r.PostForm.Get("megabytes"))
		if err != nil || sizeMiB < 1 || sizeMiB > speedtest.MaxMiB {
			http.Error(w, "حجم تست باید بین ۱ تا ۳۲ مگابایت باشد.", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 305*time.Second)
		defer cancel()
		if _, err := h.manager.RunSpeedTest(ctx, sizeMiB); err != nil {
			h.redirectWithDetail(w, r, "speedtest-failed", err.Error())
			return
		}
		http.Redirect(w, r, "/?notice=speedtest-completed", http.StatusSeeOther)
	case "/service/action":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		_, current, ok := h.requirePostSession(w, r)
		if !ok { return }
		if h.manager == nil {
			http.Error(w, "مدیریت سرویس از این پنل در دسترس نیست.", http.StatusNotFound)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		action := r.PostForm.Get("action")
		if r.PostForm.Get("confirm") != "yes" || (action != "start" && action != "stop" && action != "restart") {
			http.Error(w, "عملیات یا تأیید آن معتبر نیست.", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		if err := h.manager.ServiceAction(ctx, action); err != nil {
			h.redirectWithDetail(w, r, "operation-failed", err.Error())
			return
		}
		http.Redirect(w, r, "/?notice=service-"+action, http.StatusSeeOther)
	case "/config/apply":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		_, current, ok := h.requirePostSession(w, r)
		if !ok { return }
		if h.manager == nil {
			http.Error(w, "ویرایش تنظیمات از این پنل در دسترس نیست.", http.StatusNotFound)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("confirm") != "yes" {
			http.Error(w, "تأیید اعمال تنظیمات الزامی است.", http.StatusBadRequest)
			return
		}
		cfg := adminapi.TunnelConfiguration{
			ListenAddress: r.PostForm.Get("listen_address"),
			MaxClients: 1,
			PeerPrefixes: r.PostForm.Get("peer_prefixes"),
			LocalPrefixes: r.PostForm.Get("local_prefixes"),
			PeerIdentity: r.PostForm.Get("peer_identity"),
			ServerAddress: r.PostForm.Get("server_address"),
			ServerName: r.PostForm.Get("server_name"),
			RemotePrefixes: r.PostForm.Get("remote_prefixes"),
			AllowedDstPorts: r.PostForm.Get("allowed_dst_ports"),
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if err := h.manager.ApplyConfiguration(ctx, cfg); err != nil {
			h.redirectWithDetail(w, r, "config-failed", err.Error())
			return
		}
		http.Redirect(w, r, "/?notice=config-applied", http.StatusSeeOther)
	case "/peers/disconnect":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		_, current, ok := h.requirePostSession(w, r)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		identity := r.PostForm.Get("identity")
		if len(identity) == 0 || len(identity) > 128 || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		notice := "peer-not-found"
		if h.controller.DisconnectPeer(identity) {
			notice = "peer-disconnected"
		}
		http.Redirect(w, r, "/?notice="+notice, http.StatusSeeOther)
	case "/logout":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		id, current, ok := h.requirePostSession(w, r)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || !secureEqual(r.PostForm.Get("csrf"), current.CSRF) {
			http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		delete(h.sessions, id)
		h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0),
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, h.allowedPublicHost) {
		http.Error(w, "مبدأ درخواست پذیرفته نشد.", http.StatusForbidden)
		return
	}
	if h.loginBlocked(r) {
		replyLoginRateLimited(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
		return
	}
	if !secureEqual(r.PostForm.Get("token"), string(h.token)) {
		if h.recordLoginFailure(r) {
			replyLoginRateLimited(w)
			return
		}
		h.renderLogin(w, "توکن نامعتبر است.")
		return
	}
	h.clearLoginFailures(r)
	id, err := randomToken()
	if err != nil {
		http.Error(w, "ایجاد نشست ممکن نشد.", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "ایجاد نشست ممکن نشد.", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(sessionLifetime)
	h.mu.Lock()
	for oldID, oldSession := range h.sessions {
		if !time.Now().Before(oldSession.ExpiresAt) {
			delete(h.sessions, oldID)
		}
	}
	if len(h.sessions) >= maxSessions {
		h.mu.Unlock()
		http.Error(w, "ظرفیت نشست‌های مدیریت پر است؛ کمی بعد دوباره تلاش کنید.", http.StatusServiceUnavailable)
		return
	}
	h.sessions[id] = session{CSRF: csrf, ExpiresAt: expires}
	h.mu.Unlock()

	// Cookies are Secure whenever the request is served over TLS.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionLifetime.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loginClientKey groups attempts by the connecting IP. The panel only binds
// loopback, so remote operators should use an encrypted tunnel.
func loginClientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return ip.Unmap().String()
}

func (h *Handler) loginBlocked(r *http.Request) bool {
	key := loginClientKey(r.RemoteAddr)
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if now.Before(h.loginOverflowUntil) {
		return true
	}
	attempt, ok := h.loginAttempts[key]
	if !ok {
		return false
	}
	if now.Before(attempt.BlockedUntil) {
		return true
	}
	if !now.Before(attempt.WindowEnds) {
		delete(h.loginAttempts, key)
		return false
	}
	return false
}

// recordLoginFailure returns true once the per-IP failure budget is exhausted.
// Entries and the number of tracked clients are bounded to avoid unbounded growth.
func (h *Handler) recordLoginFailure(r *http.Request) bool {
	key := loginClientKey(r.RemoteAddr)
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()

	for oldKey, attempt := range h.loginAttempts {
		if !now.Before(attempt.WindowEnds) && !now.Before(attempt.BlockedUntil) {
			delete(h.loginAttempts, oldKey)
		}
	}
	attempt, exists := h.loginAttempts[key]
	if !exists {
		if len(h.loginAttempts) >= maxLoginEntries {
			// Fail closed if the bounded per-client table fills up.
			h.loginOverflowUntil = now.Add(loginWindow)
			return true
		}
		attempt = loginAttempt{WindowEnds: now.Add(loginWindow)}
	} else if !now.Before(attempt.WindowEnds) {
		attempt = loginAttempt{WindowEnds: now.Add(loginWindow)}
	}
	attempt.Failures++
	if attempt.Failures >= loginFailureLimit {
		attempt.BlockedUntil = now.Add(loginWindow)
		attempt.WindowEnds = attempt.BlockedUntil
	}
	h.loginAttempts[key] = attempt
	return !attempt.BlockedUntil.IsZero() && now.Before(attempt.BlockedUntil)
}

func (h *Handler) clearLoginFailures(r *http.Request) {
	h.mu.Lock()
	delete(h.loginAttempts, loginClientKey(r.RemoteAddr))
	h.mu.Unlock()
}

func replyLoginRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(loginWindow.Seconds())))
	http.Error(w, "تلاش‌های ورود بیش از حد مجاز است؛ یک دقیقه بعد دوباره تلاش کنید.", http.StatusTooManyRequests)
}

func (h *Handler) renderLogin(w http.ResponseWriter, errorText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, struct{ Error string }{Error: errorText})
}

func (h *Handler) sessionFor(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", session{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	current, ok := h.sessions[cookie.Value]
	if !ok {
		return "", session{}, false
	}
	if !time.Now().Before(current.ExpiresAt) {
		delete(h.sessions, cookie.Value)
		return "", session{}, false
	}
	return cookie.Value, current, true
}

func (h *Handler) requirePostSession(w http.ResponseWriter, r *http.Request) (string, session, bool) {
	id, current, ok := h.sessionFor(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", session{}, false
	}
	if !sameOrigin(r) {
		http.Error(w, "مبدأ درخواست پذیرفته نشد.", http.StatusForbidden)
		return "", session{}, false
	}
	return id, current, true
}

func sameOrigin(r *http.Request, allowedPublicHost string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || r.Host == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	if isLoopbackHost(u.Host) && isLoopbackHost(r.Host) {
		return u.Scheme == "http" || (u.Scheme == "https" && r.TLS != nil)
	}
	// Public access requires TLS and an explicit literal-IP allowlist. This
	// rejects arbitrary Host/Origin pairs used by DNS-rebinding attacks.
	if allowedPublicHost == "" || u.Scheme != "https" || r.TLS == nil {
		return false
	}
	host := r.Host
	if parsed, _, err := net.SplitHostPort(r.Host); err == nil {
		host = parsed
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	allowed, err := netip.ParseAddr(allowedPublicHost)
	return err == nil && ip == allowed
}

func isLoopbackHost(hostport string) bool {
	host := strings.Trim(hostport, "[]")
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func secureEqual(given, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}

func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func noticeMessage(notice string) string {
	switch notice {
	case "peer-disconnected":
		return "درخواست قطع اتصال ارسال شد."
	case "peer-not-found":
		return "این همتا دیگر متصل نیست."
	case "service-start":
		return "سرویس راه‌اندازی شد."
	case "service-stop":
		return "سرویس متوقف شد."
	case "service-restart":
		return "سرویس مجدداً راه‌اندازی شد."
	case "config-applied":
		return "تنظیمات ذخیره شد؛ در صورت فعال‌بودن سرویس، راه‌اندازی مجدد هم موفق بود."
	case "speedtest-completed":
		return "تست سرعت تونل کامل شد؛ نتایج در پایین صفحه نمایش داده می‌شود."
	case "speedtest-failed":
		return "تست سرعت کامل نشد."
	case "logs-failed":
		return "خواندن لاگ سرویس ناموفق بود."
	case "operation-failed", "config-failed":
		return "عملیات انجام نشد."
	default:
		return ""
	}
}

func safeNoticeDetail(detail string) string {
	if len(detail) > 400 { detail = detail[:400] }
	return strings.ReplaceAll(strings.TrimSpace(detail), "\x00", "")
}

func (h *Handler) redirectWithDetail(w http.ResponseWriter, r *http.Request, notice, detail string) {
	if len(detail) > 400 { detail = detail[:400] }
	target := "/?notice=" + url.QueryEscape(notice) + "&detail=" + url.QueryEscape(detail)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "روش درخواست پشتیبانی نمی‌شود.", http.StatusMethodNotAllowed)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}
