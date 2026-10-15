package adminui

import (
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
)

const (
	sessionCookieName = "pqtunnel_admin_session"
	sessionLifetime   = 12 * time.Hour
	maxSessions       = 128
)

var (
	errSessionLimit = errors.New("admin session limit reached")
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
</main></body></html>`)),
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
</style></head>
<body><main class="wrap">
<header><div><h1>پنل مدیریت PQTunnel</h1><p class="sub">وضعیت سرویس و همتایان متصل · کنترل محدود و امن</p></div>
<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">خروج از پنل</button></form></header>
{{if .Notice}}<div class="notice" role="status">{{.Notice}}</div>{{end}}
<section class="grid" aria-label="خلاصه وضعیت">
<div class="card"><div class="kicker">وضعیت تونل</div><div class="metric status"><span class="dot {{if .Snapshot.Running}}up{{end}}"></span>{{if .Snapshot.Running}}فعال{{else}}متوقف / در حال راه‌اندازی{{end}}</div></div>
<div class="card"><div class="kicker">همتایان متصل</div><div class="metric">{{len .Snapshot.Peers}} / {{.Snapshot.MaxClients}}</div></div>
<div class="card"><div class="kicker">مدت اجرای جاری</div><div class="metric">{{if .Snapshot.Uptime}}{{.Snapshot.Uptime}}{{else}}—{{end}}</div></div>
<div class="card"><div class="kicker">حالت تونل</div><div class="metric">{{if .Snapshot.SiteToSite}}سایت‌به‌سایت{{else}}میزبان / کلاینت{{end}}</div></div>
</section>
<section class="section"><h2>پیکربندی مؤثر</h2><div class="details">
<div class="detail"><span class="kicker">نشانی شنونده</span><b>{{.Snapshot.ListenAddress}}</b></div>
<div class="detail"><span class="kicker">هویت همتای مورد انتظار</span><b>{{if .Snapshot.PeerIdentity}}{{.Snapshot.PeerIdentity}}{{else}}تنظیم نشده{{end}}</b></div>
<div class="detail"><span class="kicker">محدوده‌های مجاز</span><b>محلی: {{.Snapshot.LocalPrefixCount}} · همتا: {{.Snapshot.PeerPrefixCount}}</b></div>
</div></section>
<section class="section"><h2>همتایان متصل</h2>
{{if .Snapshot.Peers}}<table><thead><tr><th>هویت گواهی</th><th>مدت اتصال</th><th>عملیات</th></tr></thead><tbody>
{{range .Snapshot.Peers}}<tr><td class="identity" data-label="هویت">{{.Identity}}</td><td data-label="مدت اتصال">{{.ConnectedFor}}</td><td><form method="post" action="/peers/disconnect" class="peerform"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="identity" value="{{.Identity}}"><button class="danger" type="submit">قطع اتصال</button></form></td></tr>{{end}}
</tbody></table>{{else}}<div class="empty">در حال حاضر هیچ همتای احراز هویت‌شده‌ای متصل نیست.</div>{{end}}
</section>
<footer>این پنل فقط وضعیت را نمایش می‌دهد و اتصال همتا را قطع می‌کند؛ مسیرها، فایروال، NAT، گواهی‌ها و کلیدها را تغییر نمی‌دهد. پنل باید فقط روی loopback در دسترس باشد.</footer>
</main></body></html>`)),
)

type session struct {
	CSRF      string
	ExpiresAt time.Time
}

// Handler serves a token-protected local management UI with short-lived,
// in-memory sessions and CSRF protection for state-changing form posts.
type Handler struct {
	token      []byte
	controller adminapi.Controller
	mu         sync.Mutex
	sessions   map[string]session
}

func New(token string, controller adminapi.Controller) (*Handler, error) {
	if len([]byte(token)) < 32 {
		return nil, errors.New("admin token must contain at least 32 bytes")
	}
	if controller == nil {
		return nil, errors.New("admin controller is required")
	}
	return &Handler{
		token: []byte(token), controller: controller, sessions: make(map[string]session),
	}, nil
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
		data := struct {
			Snapshot adminapi.Snapshot
			CSRF     string
			Notice   string
		}{
			Snapshot: h.controller.AdminSnapshot(),
			CSRF:     current.CSRF,
			Notice:   noticeMessage(r.URL.Query().Get("notice")),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dashboardTemplate.Execute(w, data); err != nil {
			return
		}
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
	if !sameOrigin(r) {
		http.Error(w, "مبدأ درخواست پذیرفته نشد.", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
		return
	}
	if !secureEqual(r.PostForm.Get("token"), string(h.token)) {
		h.renderLogin(w, "توکن نامعتبر است.")
		return
	}
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

	// Secure is intentionally false because this handler refuses non-loopback
	// binds and serves plain HTTP only there. Remote access should be tunneled.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionLifetime.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || r.Host == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme != "http" || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	return u.Path == "" || u.Path == "/"
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
	default:
		return ""
	}
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
