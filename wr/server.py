# -*- coding: utf-8 -*-
"""
File Server - Desktop Version (Final - No Folder Upload)
- Browse all drives (This PC)
- Upload ALWAYS goes to ~/Downloads
- Chunked upload (any file size, GB+)
- Supports ALL file types
"""
import http.server
import socketserver
import os
import re
import io
import tempfile
import time
import json
import hmac
import hashlib
import secrets
import socket
import shutil
import threading
import urllib.parse
import mimetypes
import html as html_lib
import webbrowser
from collections import defaultdict, deque

# ==================== CONFIG ====================
PORT = 8080
IDLE_TIMEOUT = 900
PASSWORD = "mypass1234"
MAX_LOGIN_ATTEMPTS = 5
AUTO_BAN_MINUTES = 30
RATE_WINDOW = 60
RATE_MAX_REQ = 120

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, ".server_data.json")
SECURITY_FILE = os.path.join(BASE_DIR, ".server_security.json")

ADMIN_KEY = secrets.token_hex(16)

# ==================== UPLOAD DIR ====================
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
try:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
except Exception:
    pass

CHUNKS_DIR = os.path.join(BASE_DIR, ".upload_chunks")
try:
    os.makedirs(CHUNKS_DIR, exist_ok=True)
except Exception:
    pass

# ==================== DRIVES ====================
def list_drives():
    drives = []
    if os.name == "nt":
        import string
        for letter in string.ascii_uppercase:
            d = letter + ":\\"
            if os.path.exists(d):
                drives.append(d)
    else:
        drives = ["/"]
    return drives

# ==================== EXT ====================
VIDEO_EXT = {".mp4",".mkv",".avi",".mov",".webm",".flv",".wmv",".m4v",".3gp"}
AUDIO_EXT = {".mp3",".wav",".m4a",".ogg",".aac",".flac",".opus",".amr"}
IMAGE_EXT = {".jpg",".jpeg",".png",".gif",".bmp",".webp",".svg",".ico",".heic",".heif"}
TEXT_EXT  = {".txt",".md",".log",".csv",".json",".xml",".html",".htm"}

VIDEO_MIME = {
    ".mp4":"video/mp4", ".mkv":"video/x-matroska", ".avi":"video/x-msvideo",
    ".mov":"video/quicktime", ".webm":"video/webm", ".flv":"video/x-flv",
    ".wmv":"video/x-ms-wmv", ".m4v":"video/x-m4v", ".3gp":"video/3gpp",
}
AUDIO_MIME = {
    ".mp3":"audio/mpeg", ".wav":"audio/wav", ".m4a":"audio/mp4",
    ".ogg":"audio/ogg", ".aac":"audio/aac", ".flac":"audio/flac",
    ".opus":"audio/opus", ".amr":"audio/amr",
}
IMAGE_MIME = {
    ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png",
    ".gif":"image/gif", ".bmp":"image/bmp", ".webp":"image/webp",
    ".svg":"image/svg+xml", ".ico":"image/x-icon",
    ".heic":"image/heic", ".heif":"image/heif",
}

# ==================== PERSISTENCE ====================
data_lock = threading.Lock()

def _load(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default

def _save(path, d):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e:
        print("[!] Save error:", e)

DATA = _load(DATA_FILE, {"users": {}, "sessions": {}})
DATA.setdefault("users", {}); DATA.setdefault("sessions", {})
SEC = _load(SECURITY_FILE, {"attempts": {}, "bans": {}, "probes": {}})
SEC.setdefault("attempts", {}); SEC.setdefault("bans", {}); SEC.setdefault("probes", {})

# ==================== ACTIVITY ====================
last_activity = time.time()
activity_lock = threading.Lock()
def touch_activity():
    global last_activity
    with activity_lock:
        last_activity = time.time()

# ==================== RATE LIMIT ====================
rate_buckets = defaultdict(lambda: deque(maxlen=RATE_MAX_REQ + 50))
rate_lock = threading.Lock()
def rate_ok(ip):
    now = time.time()
    with rate_lock:
        b = rate_buckets[ip]
        while b and b[0] < now - RATE_WINDOW:
            b.popleft()
        if len(b) >= RATE_MAX_REQ:
            return False
        b.append(now)
        return True

# ==================== BANS ====================
def is_banned(ip):
    with data_lock:
        b = SEC["bans"].get(ip)
        if not b: return False
        if b.get("until", 0) < time.time():
            del SEC["bans"][ip]; _save(SECURITY_FILE, SEC); return False
        return True

def unban_ip(ip):
    with data_lock:
        SEC["bans"].pop(ip, None); SEC["attempts"].pop(ip, None)
        _save(SECURITY_FILE, SEC)

def register_failed_login(ip):
    with data_lock:
        a = SEC["attempts"].get(ip, {"count": 0, "first": time.time()})
        if time.time() - a["first"] > 3600:
            a = {"count": 0, "first": time.time()}
        a["count"] += 1
        SEC["attempts"][ip] = a
        _save(SECURITY_FILE, SEC)
        if a["count"] >= MAX_LOGIN_ATTEMPTS:
            SEC["bans"][ip] = {"until": time.time() + AUTO_BAN_MINUTES*60,
                               "reason": "brute_force", "at": time.time()}
            _save(SECURITY_FILE, SEC); return True
    return False

def clear_failed_login(ip):
    with data_lock:
        SEC["attempts"].pop(ip, None); _save(SECURITY_FILE, SEC)

def register_probe(ip, path):
    with data_lock:
        p = SEC["probes"].get(ip, {"count": 0, "paths": [], "first": time.time()})
        if time.time() - p["first"] > 3600:
            p = {"count": 0, "paths": [], "first": time.time()}
        p["count"] += 1
        p["paths"] = (p["paths"] + [path])[-20:]
        SEC["probes"][ip] = p
        _save(SECURITY_FILE, SEC)
        if p["count"] >= 20:
            SEC["bans"][ip] = {"until": time.time() + AUTO_BAN_MINUTES*60,
                               "reason": "scanning", "at": time.time()}
            _save(SECURITY_FILE, SEC); return True
    return False

# ==================== SESSIONS ====================
SESSION_TTL = 86400
def _sign(p):
    return hmac.new(ADMIN_KEY.encode(), p.encode(), hashlib.sha256).hexdigest()[:32]

def create_session(ip, admin=False):
    raw = f"{ip}|{time.time()}|{secrets.token_hex(8)}|{'A' if admin else 'U'}"
    token = _sign(raw) + secrets.token_hex(8)
    with data_lock:
        DATA["sessions"][token] = {
            "ip": ip,
            "exp": time.time() + (SESSION_TTL * 7 if admin else SESSION_TTL),
            "admin": admin,
        }
        _save(DATA_FILE, DATA)
    return token

def get_session(token):
    if not token or len(token) > 128: return None
    with data_lock:
        s = DATA["sessions"].get(token)
        if not s: return None
        if s.get("exp", 0) < time.time():
            del DATA["sessions"][token]; _save(DATA_FILE, DATA); return None
        return dict(s)

def clear_user_sessions(ip):
    with data_lock:
        dead = [t for t,s in DATA["sessions"].items()
                if s.get("ip")==ip and not s.get("admin")]
        for t in dead: del DATA["sessions"][t]
        if dead: _save(DATA_FILE, DATA)

def cleanup_sessions():
    now = time.time()
    with data_lock:
        exp = [t for t,s in DATA["sessions"].items() if s.get("exp",0) < now]
        for t in exp: del DATA["sessions"][t]
        if exp: _save(DATA_FILE, DATA)

# ==================== USERS ====================
def get_client_ip(handler):
    xff = handler.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    xri = handler.headers.get("X-Real-IP")
    if xri: return xri.strip()
    return handler.client_address[0]

def get_user(ip):
    with data_lock:
        u = DATA["users"].get(ip)
        if not u:
            u = {"ip": ip, "status": "pending",
                 "perms": {"download": True, "open": True, "upload": True,
                           "types": ["video","audio","image","text","pdf","other"]},
                 "first_seen": time.time(), "last_seen": time.time(),
                 "note": "", "logins": 0}
            DATA["users"][ip] = u
            _save(DATA_FILE, DATA)
        else:
            u["last_seen"] = time.time()
        return dict(u)

def update_user(ip, **kw):
    with data_lock:
        u = DATA["users"].get(ip)
        if not u: return
        for k, v in kw.items():
            if k == "perms" and isinstance(v, dict):
                u.setdefault("perms", {}).update(v)
            else: u[k] = v
        _save(DATA_FILE, DATA)

def bump_logins(ip):
    with data_lock:
        u = DATA["users"].get(ip)
        if u:
            u["logins"] = u.get("logins", 0) + 1
            _save(DATA_FILE, DATA)

def is_user_allowed(ip):
    u = get_user(ip)
    if u["status"] == "blocked": return False, "blocked"
    if u["status"] == "pending": return False, "pending"
    return True, "ok"

# ==================== TOKENS ====================
def get_token(handler):
    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query)
    t = qs.get("t", [None])[0]
    if t:
        s = get_session(t)
        if s and not s.get("admin"): return t
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"(?:^|;\s*)session=([A-Za-z0-9]+)", cookie)
    if m:
        s = get_session(m.group(1))
        if s and not s.get("admin"): return m.group(1)
    return None

def get_admin_token(handler):
    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query)
    t = qs.get("a", [None])[0]
    if t:
        s = get_session(t)
        if s and s.get("admin"): return t
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"(?:^|;\s*)admin=([A-Za-z0-9]+)", cookie)
    if m:
        s = get_session(m.group(1))
        if s and s.get("admin"): return m.group(1)
    return None

def is_valid_admin_path(path):
    exp = "/panel_" + ADMIN_KEY
    return path == exp or path.startswith(exp + "/")

# ==================== CSRF ====================
def csrf_token(session_token):
    return hmac.new(ADMIN_KEY.encode(),
                    ("csrf|" + session_token).encode(),
                    hashlib.sha256).hexdigest()[:24]

def check_csrf(handler, session_token, form):
    got = form.get("csrf", [""])[0]
    want = csrf_token(session_token)
    return hmac.compare_digest(got, want)

# ==================== HELPERS ====================
def get_mime(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in VIDEO_MIME: return VIDEO_MIME[ext]
    if ext in AUDIO_MIME: return AUDIO_MIME[ext]
    if ext in IMAGE_MIME: return IMAGE_MIME[ext]
    if ext == ".pdf": return "application/pdf"
    if ext in (".txt",".md",".log",".csv"): return "text/plain; charset=utf-8"
    if ext == ".json": return "application/json"
    if ext == ".xml": return "application/xml"
    if ext in (".html",".htm"): return "text/html; charset=utf-8"
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"

def human_size(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def file_category(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in VIDEO_EXT: return "video"
    if ext in AUDIO_EXT: return "audio"
    if ext in IMAGE_EXT: return "image"
    if ext == ".pdf": return "pdf"
    if ext in TEXT_EXT: return "text"
    return "other"

def safe_filename(name):
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)
    name = name.strip(". ")
    return name

def unique_path(dir_path, fname):
    dest = os.path.join(dir_path, fname)
    if not os.path.exists(dest):
        return dest
    base, ext = os.path.splitext(dest)
    i = 1
    while os.path.exists(dest):
        dest = f"{base}_{i}{ext}"; i += 1
    return dest

# ==================== HTML ====================
BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0d12;--panel:#141821;--panel2:#1a1f2b;--border:#242a38;
  --text:#e8eaf0;--muted:#8a93a6;--accent:#22d47b;--accent2:#16a34a;
  --blue:#3b82f6;--red:#ef4444;--yellow:#f59e0b;--radius:12px;
}
[data-theme="light"]{
  --bg:#f4f6fa;--panel:#ffffff;--panel2:#f8fafc;--border:#e2e8f0;
  --text:#0f172a;--muted:#64748b;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;
     font-size:14px}
a{color:var(--accent);text-decoration:none}
.layout{display:flex;min-height:100vh}
.sidebar{width:230px;background:var(--panel);border-right:1px solid var(--border);
         padding:16px 0;position:sticky;top:0;height:100vh;overflow-y:auto;
         flex-shrink:0}
.sidebar .brand{padding:0 18px 14px;font-size:16px;font-weight:700;
                color:var(--accent);display:flex;align-items:center;gap:8px;
                border-bottom:1px solid var(--border);margin-bottom:10px;
                letter-spacing:1px}
.sidebar nav a{display:flex;align-items:center;gap:10px;padding:9px 18px;
               color:var(--text);font-size:13px;font-weight:500;
               border-left:3px solid transparent;transition:.15s}
.sidebar nav a:hover{background:var(--panel2);color:var(--accent);
                     border-left-color:var(--accent)}
.sidebar nav a.active{background:var(--panel2);color:var(--accent);
                      border-left-color:var(--accent)}
.sidebar .bottom{padding:12px 18px;border-top:1px solid var(--border);
                 margin-top:12px;font-size:12px;color:var(--muted)}
.social-links{display:flex;flex-direction:column;gap:1px;margin-top:10px;
              border-top:1px solid var(--border);padding-top:8px}
.social-links a{display:flex;align-items:center;gap:8px;padding:7px 18px;
                color:var(--muted);font-size:12px;
                border-left:3px solid transparent;transition:.15s}
.social-links a:hover{color:var(--accent);background:var(--panel2);
                      border-left-color:var(--accent)}
.social-title{padding:4px 18px 6px;color:var(--muted);font-size:10px;
              text-transform:uppercase;letter-spacing:1px}
.main{flex:1;padding:18px;max-width:100%;overflow-x:hidden}
.topbar{display:flex;justify-content:space-between;align-items:center;
        gap:10px;margin-bottom:12px;flex-wrap:wrap}
.topbar h1{font-size:17px;font-weight:700}
.topbar .actions{display:flex;gap:6px;flex-wrap:wrap}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));
       gap:8px;margin-bottom:12px}
.stat{background:var(--panel);border:1px solid var(--border);
      border-radius:10px;padding:10px 12px}
.stat .label{color:var(--muted);font-size:10px;text-transform:uppercase;
             letter-spacing:.4px;margin-bottom:2px}
.stat .value{font-size:15px;font-weight:700;color:var(--accent)}
.card{background:var(--panel);border:1px solid var(--border);
      border-radius:10px;padding:14px;margin-bottom:10px}
.card h2{font-size:13px;font-weight:600;margin-bottom:10px}
.btn{background:var(--accent);color:#0b0d12;border:0;padding:7px 12px;
     border-radius:7px;cursor:pointer;font-size:12px;font-weight:600;
     text-decoration:none;display:inline-flex;align-items:center;gap:5px;
     transition:.15s;white-space:nowrap}
.btn:hover{background:var(--accent2);color:#fff}
.btn.red{background:var(--red);color:#fff}
.btn.blue{background:var(--blue);color:#fff}
.btn.yellow{background:var(--yellow);color:#0b0d12}
.btn.gray{background:var(--panel2);color:var(--text);border:1px solid var(--border)}
.btn.sm{padding:4px 9px;font-size:11px}
.input{width:100%;padding:8px 11px;border-radius:7px;
       border:1px solid var(--border);background:var(--panel2);
       color:var(--text);font-size:13px;outline:none}
.breadcrumb{background:var(--panel);border:1px solid var(--border);
            border-radius:10px;padding:8px 12px;margin-bottom:10px;
            font-size:12px;color:var(--muted);word-break:break-all;
            display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.breadcrumb a{color:var(--accent)}
.filelist{background:var(--panel);border:1px solid var(--border);
          border-radius:10px;overflow:hidden}
.filerow{display:flex;align-items:center;gap:10px;padding:9px 12px;
         border-bottom:1px solid var(--border);flex-wrap:wrap}
.filerow:last-child{border-bottom:none}
.filerow:hover{background:var(--panel2)}
.fileicon{width:32px;height:32px;border-radius:8px;display:flex;
          align-items:center;justify-content:center;font-size:17px;
          background:var(--panel2);flex-shrink:0}
.fileicon.dir{background:rgba(245,158,11,.15)}
.fileicon.video{background:rgba(239,68,68,.15)}
.fileicon.audio{background:rgba(139,92,246,.15)}
.fileicon.image{background:rgba(34,212,123,.15)}
.fileicon.text{background:rgba(59,130,246,.15)}
.fileicon.pdf{background:rgba(239,68,68,.15)}
.filename{flex:1;font-size:13px;color:var(--text);min-width:100px;
          word-break:break-all}
.filename:hover{color:var(--accent)}
.filename.dir{font-weight:600;color:var(--yellow)}
.filesize{color:var(--muted);font-size:11px;white-space:nowrap}
.fileactions{display:flex;gap:5px;flex-shrink:0}
.grid-view{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
           gap:10px;padding:12px;background:var(--panel);
           border:1px solid var(--border);border-radius:10px}
.grid-item{background:var(--panel2);border:1px solid var(--border);
           border-radius:9px;padding:11px;text-align:center;
           transition:.15s;cursor:pointer;overflow:hidden}
.grid-item:hover{transform:translateY(-2px);border-color:var(--accent)}
.grid-item .gi-icon{font-size:26px;margin-bottom:5px}
.grid-item .gi-name{font-size:11px;word-break:break-all;line-height:1.3;
                    max-height:32px;overflow:hidden}
.grid-item .gi-size{color:var(--muted);font-size:10px;margin-top:4px}
.empty{text-align:center;padding:40px 16px;color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--accent);font-weight:600;background:var(--panel2);
   font-size:11px;text-transform:uppercase;letter-spacing:.4px}
tr:hover{background:var(--panel2)}
.badge{padding:2px 8px;border-radius:20px;font-size:10px;
       font-weight:600;display:inline-block}
.badge.ok{background:rgba(34,212,123,.15);color:var(--accent)}
.badge.pending{background:rgba(245,158,11,.15);color:var(--yellow)}
.badge.blocked{background:rgba(239,68,68,.15);color:var(--red)}
.login-wrap{min-height:100vh;display:flex;align-items:center;
            justify-content:center;padding:20px}
.login-box{background:var(--panel);border:1px solid var(--border);
           border-radius:16px;padding:30px 24px;width:100%;max-width:380px;
           box-shadow:0 12px 40px rgba(0,0,0,.3)}
.login-box h2{color:var(--accent);font-size:18px;margin-bottom:4px;
              text-align:center}
.login-box .sub{color:var(--muted);font-size:12px;text-align:center;
                margin-bottom:20px}
.login-box .field{margin-bottom:12px}
.login-box .msg{padding:9px 12px;border-radius:7px;font-size:12px;
                margin-top:12px;text-align:center}
.login-box .msg.error{background:rgba(239,68,68,.15);color:var(--red)}
.mobile-menu-btn{display:inline-flex;background:var(--panel);
                 border:1px solid var(--border);color:var(--text);
                 padding:7px 12px;border-radius:7px;cursor:pointer;
                 font-size:16px}
.copyright{text-align:center;color:var(--muted);font-size:11px;
           margin-top:14px;padding:14px 12px;border-top:1px solid var(--border)}
.copyright b{color:var(--accent);font-weight:700;letter-spacing:2px}
.upload-box{background:var(--panel);border:1px dashed var(--border);
            border-radius:10px;padding:14px;margin-bottom:12px;
            display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.upload-box input[type=file]{display:none}
.upload-box label{background:var(--blue);color:#fff;padding:8px 14px;
                  border-radius:7px;cursor:pointer;font-size:12px;
                  font-weight:600}
.upload-box .fname{color:var(--muted);font-size:12px;flex:1;
                   word-break:break-all;min-width:100px}
.upload-box .up-btn{background:var(--accent);color:#0b0d12;display:none}
.upload-box .up-btn.show{display:inline-flex}
.upload-box .pbar{width:100%;height:6px;background:var(--panel2);
                  border-radius:3px;overflow:hidden;display:none;margin-top:8px}
.upload-box .pbar.show{display:block}
.upload-box .pbar div{height:100%;background:var(--accent);width:0%;
                      transition:width .2s}
.upload-box .status{width:100%;font-size:12px;display:none;word-break:break-all}
.upload-box .status.show{display:block}
.thumb{width:40px;height:40px;border-radius:6px;object-fit:cover;
       background:var(--panel2);flex-shrink:0}
.drive-item{display:flex;align-items:center;gap:14px;padding:14px 16px;
            border-bottom:1px solid var(--border)}
.drive-item:hover{background:var(--panel2)}
.drive-icon{font-size:32px;width:48px;text-align:center}
.drive-info{flex:1}
.drive-name{font-size:14px;font-weight:600;color:var(--yellow)}
.drive-info .drive-name:hover{color:var(--accent)}
.drive-meta{color:var(--muted);font-size:11px;margin-top:3px}
.bar{width:100%;height:6px;background:var(--panel2);border-radius:3px;
     overflow:hidden;margin-top:6px}
.bar div{height:100%;background:var(--accent)}
@media (max-width:768px){
  .sidebar{position:fixed;z-index:100;transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .main{padding:12px}
}
"""

def page_top(title):
    return f'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_lib.escape(title)}</title>
<style>{BASE_CSS}</style></head><body>'''

def page_bottom(token=""):
    return f'''
<div class="copyright">© 2025 <b>M7L TEAM SERVER</b> — All Rights Reserved</div>
<script>
window.__TOKEN__ = "{token}";
try{{
  const saved = localStorage.getItem('theme');
  if(saved) document.documentElement.setAttribute('data-theme', saved);
}}catch(e){{}}
function toggleTheme(){{
  const html = document.documentElement;
  const cur = html.getAttribute('data-theme') || 'dark';
  const next = cur === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
  try{{ localStorage.setItem('theme', next); }}catch(e){{}}
}}
function toggleSidebarCollapse(){{
  const sb = document.querySelector('.sidebar');
  if(!sb) return;
  sb.classList.toggle('open');
}}
function goHome(){{
  const u = new URL(location.href);
  u.pathname = '/'; u.searchParams.delete('view');
  location.href = u.toString();
}}
function filterFiles(){{
  const q = (document.getElementById('searchInput')||{{}}).value || '';
  const ql = q.toLowerCase();
  document.querySelectorAll('.filerow, .grid-item').forEach(el=>{{
    const n = (el.getAttribute('data-name')||'').toLowerCase();
    el.style.display = n.includes(ql) ? '' : 'none';
  }});
}}
function onFilePick(input, btnId){{
  const box = input.closest('.upload-box');
  const fname = box.querySelector('.fname');
  const status = box.querySelector('.status');
  box.querySelectorAll('.up-btn').forEach(b => b.classList.remove('show'));
  const btn = btnId ? box.querySelector('#' + btnId) : null;
  if(input.files.length){{
    fname.textContent = input.files.length + ' file(s): ' +
      Array.from(input.files).slice(0,3).map(f=>f.name).join(', ') +
      (input.files.length>3?' ...':'');
    if(btn) btn.classList.add('show');
  }} else {{
    fname.textContent = 'No file selected';
  }}
  status.classList.remove('show');
}}

const CHUNK_SIZE = 5 * 1024 * 1024;  // 5 MB

function uploadFiles(inputId, pathB64){{
  const input = document.getElementById(inputId);
  const box = input.closest('.upload-box');
  const btn = box.querySelector('.up-btn.show') || box.querySelector('.up-btn');
  const pbar = box.querySelector('.pbar');
  const pb = pbar.querySelector('div');
  const status = box.querySelector('.status');
  if(!input.files.length) return;

  let token = window.__TOKEN__ || '';
  if(!token){{
    try {{
      const u = new URL(location.href);
      token = u.searchParams.get('t') || '';
    }} catch(e){{}}
  }}

  const files = Array.from(input.files);
  let totalSize = 0;
  files.forEach(f => totalSize += f.size);

  let totalUploaded = 0;
  btn.disabled = true;
  btn.textContent = 'Uploading...';
  pbar.classList.add('show');
  status.classList.add('show');
  status.style.color = 'var(--muted)';

  function humanMB(n){{
    if(n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
    if(n < 1024*1024*1024) return (n/(1024*1024)).toFixed(1) + ' MB';
    return (n/(1024*1024*1024)).toFixed(2) + ' GB';
  }}

  function uploadOne(file, fileIndex){{
    return new Promise((resolve, reject) => {{
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
      const uploadId = 'up_' + Date.now() + '_' + Math.random().toString(36).slice(2);
      let chunkIndex = 0;

      function sendChunk(){{
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        const xhr = new XMLHttpRequest();
        const url = '/upload_chunk?t=' + encodeURIComponent(token)
                  + '&id=' + encodeURIComponent(uploadId)
                  + '&name=' + encodeURIComponent(file.name)
                  + '&idx=' + chunkIndex
                  + '&total=' + totalChunks;
        xhr.open('POST', url);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');

        xhr.upload.onprogress = (e) => {{
          if(e.lengthComputable){{
            const currentTotal = totalUploaded + e.loaded;
            const p = totalSize > 0 ? Math.round((currentTotal / totalSize) * 100) : 0;
            pb.style.width = p + '%';
            const fileSizeTxt = humanMB(file.size);
            status.textContent = '📤 [' + (fileIndex+1) + '/' + files.length + '] '
                               + file.name + ' (' + fileSizeTxt + ') — ' + p + '%';
          }}
        }};

        xhr.onload = () => {{
          if(xhr.status >= 200 && xhr.status < 400){{
            totalUploaded += (end - start);
            chunkIndex++;
            if(chunkIndex < totalChunks){{
              sendChunk();
            }} else {{
              resolve();
            }}
          }} else {{
            reject('Chunk ' + chunkIndex + ' failed: ' + xhr.status + ' — ' + xhr.responseText.substring(0,100));
          }}
        }};
        xhr.onerror = () => reject('Network error on chunk ' + chunkIndex);
        xhr.send(chunk);
      }}
      sendChunk();
    }});
  }}

  (async () => {{
    try {{
      for(let i = 0; i < files.length; i++){{
        await uploadOne(files[i], i);
      }}
      status.style.color = 'var(--accent)';
      status.textContent = '✓ Upload complete! Saved to Downloads (' + files.length + ' file(s))';
      setTimeout(()=>location.reload(), 1200);
    }} catch(err) {{
      status.style.color = 'var(--red)';
      status.textContent = '✗ Upload failed: ' + err;
      btn.disabled = false; btn.textContent = 'Upload';
    }}
  }})();
}}

function previewText(url, name){{
  const w = window.open('', '_blank');
  fetch(url).then(r => r.text()).then(txt => {{
    const safe = txt.replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
    w.document.write('<pre style="background:#0b0d12;color:#e8eaf0;padding:20px;font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all">' + safe + '</pre>');
    w.document.title = name;
  }});
}}
</script>
</body></html>'''

def sidebar(active, base_url, extra=""):
    def c(n): return "active" if active == n else ""
    return f'''
<aside class="sidebar" id="sidebar">
  <div class="brand">🛡️ File Server</div>
  <nav>
    <a class="{c('files')}" href="{base_url}">📁 Files</a>
    {extra}
  </nav>
  <div class="social-links">
    <div class="social-title">My Accounts</div>
    <a href="https://youtube.com/@androidplus4494" target="_blank">▶️ YouTube</a>
    <a href="https://www.instagram.com/m7l.misoz" target="_blank">📸 Instagram</a>
    <a href="https://x.com/m7lmisoz" target="_blank">🐦 Twitter (X)</a>
    <a href="https://t.me/m7lmisoz" target="_blank">📱 Telegram</a>
    <a href="https://www.paypal.com/paypalme/hakrm7l" target="_blank">💝 Support</a>
  </div>
  <div class="bottom">
    <a href="javascript:toggleTheme()" style="color:var(--muted);display:flex;gap:6px;align-items:center">🌙 Theme</a>
  </div>
</aside>'''

def upload_box_html(token):
    return f'''
    <div class="upload-box">
      <input type="file" id="upfiles_{token}" multiple onchange="onFilePick(this,'upbtn_f_{token}')">
      <label for="upfiles_{token}">📄 Choose Files</label>
      <span class="fname">No file selected</span>
      <button class="btn up-btn" type="button" id="upbtn_f_{token}"
              onclick="uploadFiles('upfiles_{token}', '/')">Upload</button>
      <div class="pbar"><div></div></div>
      <div class="status"></div>
      <div style="width:100%;color:var(--muted);font-size:11px;margin-top:4px">
        Files will be saved to: <b>{html_lib.escape(UPLOAD_DIR)}</b>
        &nbsp;·&nbsp; Any type · Any size
      </div>
    </div>'''

# ==================== HANDLER ====================
class Handler(http.server.SimpleHTTPRequestHandler):

    def security_headers(self):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")

    def send_html(self, html, status=200):
        enc = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.security_headers()
        self.end_headers()
        try: self.wfile.write(enc)
        except Exception: pass

    def redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def login_page(self, error=""):
        eh = f'<div class="msg error">{html_lib.escape(error)}</div>' if error else ''
        h = page_top("Login") + f'''
        <div class="login-wrap"><div class="login-box">
          <h2>🔒 Secure Login</h2>
          <p class="sub">Enter password to continue</p>
          <form method="POST" action="/login">
            <div class="field">
              <input class="input" type="password" name="password"
                     placeholder="Password" autofocus required>
            </div>
            <button class="btn" type="submit" style="width:100%;justify-content:center;padding:11px">Sign In</button>
          </form>
          {eh}
        </div></div>''' + page_bottom()
        self.send_html(h)

    def pending_page(self, ip):
        u = get_user(ip)
        if u["status"] == "approved":
            return self.redirect("/")
        if u["status"] == "blocked":
            return self.blocked_page(ip, "banned")

        h = page_top("Pending") + f'''
        <div class="login-wrap"><div class="login-box">
          <h2 style="color:var(--yellow)">⏳ Waiting for Approval</h2>
          <p class="sub">Your access request is pending</p>
          <div style="background:var(--panel2);padding:12px;border-radius:8px;text-align:center;margin-bottom:14px">
            <div style="color:var(--muted);font-size:11px">Your IP</div>
            <div style="color:var(--accent);font-weight:700;font-size:14px">{html_lib.escape(ip)}</div>
          </div>
          <a class="btn gray" href="/" style="width:100%;justify-content:center">Refresh</a>
        </div></div>
        <script>setTimeout(function(){{ location.reload(); }}, 3000);</script>
        ''' + page_bottom()
        self.send_html(h)

    def blocked_page(self, ip, reason=""):
        h = page_top("Blocked") + f'''
        <div class="login-wrap"><div class="login-box" style="border-color:var(--red)">
          <h2 style="color:var(--red)">🚫 Access Blocked</h2>
          <p class="sub">Your IP: <b>{html_lib.escape(ip)}</b></p>
          {f'<p style="color:var(--muted);font-size:11px;text-align:center">Reason: {html_lib.escape(reason)}</p>' if reason else ''}
        </div></div>''' + page_bottom()
        self.send_html(h)

    def drives_page(self, token, perms, view="list"):
        h = page_top("This PC")
        h += '<div class="layout">'
        h += sidebar("files", f"/?t={token}")
        h += '<main class="main">'
        h += '<div class="topbar">'
        h += '<button class="mobile-menu-btn" onclick="toggleSidebarCollapse()">☰</button>'
        h += '<h1>💾 This PC</h1>'
        h += '<div class="actions"><a class="btn gray" href="/logout">Logout</a></div>'
        h += '</div>'

        if perms.get("upload", True):
            h += upload_box_html(token)

        h += '<div class="breadcrumb"><a href="/?t=' + token + '">💾 This PC</a></div>'

        h += '<div class="card" style="padding:0">'
        for d in list_drives():
            label = d.rstrip("\\/")
            try:
                total, used, free = shutil.disk_usage(d)
                info = f"{human_size(used)} / {human_size(total)} used  ({human_size(free)} free)"
                pct = int(used / total * 100) if total else 0
                bar = f'<div class="bar"><div style="width:{pct}%"></div></div>'
            except Exception:
                info = "Drive"
                bar = ""
            url = "/" + urllib.parse.quote(d.replace("\\","/")) + f"?t={token}"
            h += f'''
            <div class="drive-item">
              <div class="drive-icon">💾</div>
              <div class="drive-info">
                <a class="drive-name" href="{url}">{html_lib.escape(label)}</a>
                <div class="drive-meta">{html_lib.escape(info)}</div>
                {bar}
              </div>
              <a class="btn blue" href="{url}">Open</a>
            </div>'''
        h += '</div>'

        home = os.path.expanduser("~")
        shortcuts = [
            ("📥 Downloads", os.path.join(home, "Downloads")),
            ("🖥️ Desktop",   os.path.join(home, "Desktop")),
            ("📄 Documents", os.path.join(home, "Documents")),
            ("🖼️ Pictures",  os.path.join(home, "Pictures")),
            ("🎬 Videos",    os.path.join(home, "Videos")),
            ("🎵 Music",     os.path.join(home, "Music")),
        ]
        existing = [(l, p) for l, p in shortcuts if os.path.exists(p)]
        if existing:
            h += '<div class="card"><h2>⭐ Quick Access</h2>'
            for label, p in existing:
                url = "/" + urllib.parse.quote(p.replace("\\","/")) + f"?t={token}"
                h += f'''
                <div class="drive-item">
                  <div class="drive-icon">{label.split()[0]}</div>
                  <div class="drive-info">
                    <a class="drive-name" href="{url}">{html_lib.escape(label[2:])}</a>
                    <div class="drive-meta">{html_lib.escape(p)}</div>
                  </div>
                  <a class="btn blue" href="{url}">Open</a>
                </div>'''
            h += '</div>'

        h += '</main></div>'
        h += page_bottom(token)
        self.send_html(h)

    def list_directory(self, path, token, perms, view="list"):
        try:
            entries = sorted(os.listdir(path),
                key=lambda x: (not os.path.isdir(os.path.join(path,x)), x.lower()))
        except OSError as e:
            self.send_error(403, f"Cannot access: {e}"); return

        drive, tail = os.path.splitdrive(path)
        rel_parts = [p for p in tail.strip("\\/").split(os.sep) if p]

        total_size = 0; file_count = 0; dir_count = 0
        for e in entries:
            try:
                fp = os.path.join(path, e)
                if os.path.isdir(fp): dir_count += 1
                else:
                    file_count += 1
                    total_size += os.path.getsize(fp)
            except: pass

        h = page_top("Files")
        h += '<div class="layout">'
        h += sidebar("files", f"/?t={token}")
        h += '<main class="main">'
        h += '<div class="topbar">'
        h += '<button class="mobile-menu-btn" onclick="toggleSidebarCollapse()">☰</button>'
        h += f'<h1>📁 {html_lib.escape(os.path.basename(path.rstrip("\\/")) or path)}</h1>'
        h += '<div class="actions">'
        vt = "list" if view == "grid" else "grid"
        vl = "☰ List" if view == "grid" else "▦ Grid"
        cur_url = "/" + urllib.parse.quote(path.replace("\\","/"))
        h += f'<a class="btn gray" href="{cur_url}?t={token}&view={vt}">{vl}</a>'
        h += '<a class="btn gray" href="/logout">Logout</a>'
        h += '</div></div>'

        h += '<div class="stats">'
        h += f'<div class="stat"><div class="label">Files</div><div class="value">{file_count}</div></div>'
        h += f'<div class="stat"><div class="label">Folders</div><div class="value">{dir_count}</div></div>'
        h += f'<div class="stat"><div class="label">Size</div><div class="value">{human_size(total_size)}</div></div>'
        h += '</div>'

        if perms.get("upload", True):
            h += upload_box_html(token)

        h += '<div style="margin-bottom:10px"><input id="searchInput" class="input" placeholder="🔍 Search files..." oninput="filterFiles()"></div>'

        h += '<div class="breadcrumb"><a href="/?t=' + token + '">💾 This PC</a>'
        if drive:
            d_url = "/" + urllib.parse.quote(drive.rstrip("\\/")) + f"?t={token}"
            h += f'<span>/</span><a href="{d_url}">{html_lib.escape(drive.rstrip("\\/"))}</a>'
        acc = drive
        for p in rel_parts:
            acc = os.path.join(acc, p)
            p_url = "/" + urllib.parse.quote(acc.replace("\\","/")) + f"?t={token}"
            h += f'<span>/</span><a href="{p_url}">{html_lib.escape(p)}</a>'
        h += '</div>'

        allowed_types = set(perms.get("types", []))
        can_open = perms.get("open", True)
        can_dl = perms.get("download", True)

        items = ""
        if rel_parts:
            parent = os.path.dirname(path.rstrip("\\/"))
            if not parent.endswith(("\\","/")) and parent and not parent.endswith(":"):
                parent += os.sep
            parent_url = "/" + urllib.parse.quote(parent.replace("\\","/")) + f"?t={token}"
            if view == "grid":
                items += f'<a class="grid-item" href="{parent_url}&view=grid"><div class="gi-icon">⬅️</div><div class="gi-name">.. (up)</div></a>'
            else:
                items += f'<div class="filerow"><div class="fileicon dir">📁</div><a class="filename dir" href="{parent_url}">.. (up)</a></div>'

        if not entries and not rel_parts:
            items += '<div class="empty">📂 Empty</div>'

        for e in entries:
            full = os.path.join(path, e)
            isdir = os.path.isdir(full)
            safe = html_lib.escape(e)
            safe_attr = html_lib.escape(e, quote=True)

            if isdir:
                child_url = "/" + urllib.parse.quote(full.replace("\\","/")) + f"?t={token}&view={view}"
                if view == "grid":
                    items += f'<a class="grid-item" href="{child_url}" data-name="{safe_attr}"><div class="gi-icon">📁</div><div class="gi-name">{safe}</div></a>'
                else:
                    items += f'<div class="filerow" data-name="{safe_attr}"><div class="fileicon dir">📁</div><a class="filename dir" href="{child_url}">{safe}/</a></div>'
                continue

            try: sz = human_size(os.path.getsize(full))
            except: sz = "-"

            cat = file_category(e)
            icon = {"video":"🎬","audio":"🎵","image":"🖼️","text":"📄","pdf":"📕"}.get(cat, "📄")

            file_url = "/" + urllib.parse.quote(full.replace("\\","/")) + f"?t={token}"
            allowed = cat in allowed_types

            thumb_html = ""
            if cat == "image" and allowed:
                thumb_html = f'<img class="thumb" src="{file_url}" alt="" loading="lazy">'

            if not allowed:
                if view == "grid":
                    items += f'<div class="grid-item" style="opacity:.4" data-name="{safe_attr}"><div class="gi-icon">🔒</div><div class="gi-name">{safe}</div></div>'
                else:
                    items += f'<div class="filerow" style="opacity:.5" data-name="{safe_attr}"><div class="fileicon">🔒</div><div class="filename">{safe}</div><span class="filesize">{sz}</span><span class="badge blocked">No access</span></div>'
                continue

            actions = ""
            if can_open:
                if cat == "text":
                    safe_name_js = html_lib.escape(e, quote=True).replace("'", "\\'")
                    actions += f'<a class="btn sm blue" href="javascript:previewText(\'{file_url}\', \'{safe_name_js}\')">👁 View</a>'
                else:
                    actions += f'<a class="btn sm blue" href="{file_url}" target="_blank">👁 Open</a>'
            if can_dl:
                actions += f'<a class="btn sm" href="{file_url}&amp;dl=1">⬇ Save</a>'

            if view == "grid":
                link = file_url if can_open else (file_url + "&dl=1")
                if cat == "image":
                    items += f'<a class="grid-item" href="{file_url}" target="_blank" data-name="{safe_attr}"><img class="thumb-large" style="width:100%;height:90px;object-fit:cover;border-radius:6px;margin-bottom:6px" src="{file_url}" alt="" loading="lazy"><div class="gi-name">{safe}</div><div class="gi-size">{sz}</div></a>'
                else:
                    items += f'<a class="grid-item" href="{link}" target="_blank" data-name="{safe_attr}"><div class="gi-icon">{icon}</div><div class="gi-name">{safe}</div><div class="gi-size">{sz}</div></a>'
            else:
                if thumb_html:
                    items += f'<div class="filerow" data-name="{safe_attr}">{thumb_html}<a class="filename" href="{file_url}" target="_blank">{safe}</a><span class="filesize">{sz}</span><div class="fileactions">{actions}</div></div>'
                else:
                    items += f'<div class="filerow" data-name="{safe_attr}"><div class="fileicon {cat}">{icon}</div><a class="filename" href="{file_url}" target="_blank">{safe}</a><span class="filesize">{sz}</span><div class="fileactions">{actions}</div></div>'

        if view == "grid":
            h += f'<div class="grid-view">{items}</div>'
        else:
            h += f'<div class="filelist">{items}</div>'

        h += '</main></div>'
        h += page_bottom(token)
        self.send_html(h)

    def admin_page(self, atoken, base_path, tab="users", msg=""):
        with data_lock:
            users = list(DATA["users"].values())
            sc = len(DATA["sessions"])
            bans = dict(SEC.get("bans", {}))
            probes = dict(SEC.get("probes", {}))
        users.sort(key=lambda u: ({"pending":0,"approved":1,"blocked":2}.get(u.get("status"),1), u.get("ip","")))

        h = page_top("Admin")
        h += '<div class="layout">'
        links = f'''
          <a class="{'active' if tab=='users' else ''}" href="{base_path}?a={atoken}">👥 Users</a>
          <a class="{'active' if tab=='bans' else ''}" href="{base_path}?tab=bans&a={atoken}">🚫 Bans</a>
          <a class="{'active' if tab=='probes' else ''}" href="{base_path}?tab=probes&a={atoken}">⚠️ Probes</a>
        '''
        h += sidebar(tab, base_path + f"?a={atoken}", links)
        h += '<main class="main">'
        h += '<div class="topbar">'
        h += '<button class="mobile-menu-btn" onclick="toggleSidebarCollapse()">☰</button>'
        h += '<h1>🛡️ Admin Panel</h1>'
        h += f'<div class="actions"><a class="btn gray" href="{base_path}/logout?a={atoken}">Logout</a></div></div>'

        if msg: h += f'<div class="card" style="border-color:var(--accent)">{html_lib.escape(msg)}</div>'

        pending = sum(1 for u in users if u.get("status") == "pending")
        h += '<div class="stats">'
        h += f'<div class="stat"><div class="label">Users</div><div class="value">{len(users)}</div></div>'
        h += f'<div class="stat"><div class="label">Pending</div><div class="value" style="color:var(--yellow)">{pending}</div></div>'
        h += f'<div class="stat"><div class="label">Active</div><div class="value">{sc}</div></div>'
        h += f'<div class="stat"><div class="label">Bans</div><div class="value" style="color:var(--red)">{len(bans)}</div></div>'
        h += '</div>'

        if tab == "users":
            h += '<div class="card"><h2>👥 Users</h2>'
            if not users:
                h += '<p style="color:var(--muted)">No users yet.</p>'
            else:
                h += '<table><thead><tr><th>IP</th><th>Status</th><th>Permissions</th><th>Logins</th><th>Last Seen</th><th>Actions</th></tr></thead><tbody>'
                for u in users:
                    ip = u.get("ip",""); st = u.get("status","pending")
                    p = u.get("perms", {})
                    types = ", ".join(p.get("types", [])) or "-"
                    ps = f"DL:{'Y' if p.get('download') else 'N'} | Open:{'Y' if p.get('open') else 'N'}<br><span style='color:var(--muted);font-size:10px'>{html_lib.escape(types)}</span>"
                    badge = f'<span class="badge {st}">{st}</span>'
                    logins = u.get("logins", 0)
                    last = time.strftime("%Y-%m-%d %H:%M", time.localtime(u.get("last_seen",0)))

                    if st == "pending":
                        act = f'<a class="btn sm yellow" href="{base_path}/action?do=approve&ip={ip}&a={atoken}">Approve</a> <a class="btn sm red" href="{base_path}/action?do=block&ip={ip}&a={atoken}">Block</a>'
                    elif st == "approved":
                        act = f'<a class="btn sm red" href="{base_path}/action?do=block&ip={ip}&a={atoken}">Block</a>'
                    else:
                        act = f'<a class="btn sm" href="{base_path}/action?do=unblock&ip={ip}&a={atoken}">Unblock</a>'
                    act += f' <a class="btn sm blue" href="{base_path}/perms?ip={ip}&a={atoken}">Perms</a>'
                    h += f'<tr><td><b>{html_lib.escape(ip)}</b></td><td>{badge}</td><td style="font-size:11px">{ps}</td><td>{logins}</td><td style="font-size:10px;color:var(--muted)">{last}</td><td>{act}</td></tr>'
                h += '</tbody></table>'
            h += '</div>'

        elif tab == "bans":
            h += '<div class="card"><h2>🚫 Active Bans</h2>'
            if not bans:
                h += '<p style="color:var(--muted)">No active bans.</p>'
            else:
                h += '<table><thead><tr><th>IP</th><th>Reason</th><th>Until</th><th>Action</th></tr></thead><tbody>'
                for ip, b in bans.items():
                    until = time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("until",0)))
                    h += f'<tr><td><b>{html_lib.escape(ip)}</b></td><td>{html_lib.escape(b.get("reason",""))}</td><td>{until}</td><td><a class="btn sm" href="{base_path}/action?do=unban&ip={ip}&a={atoken}">Unban</a></td></tr>'
                h += '</tbody></table>'
            h += '</div>'

        elif tab == "probes":
            h += '<div class="card"><h2>⚠️ Probes</h2>'
            if not probes:
                h += '<p style="color:var(--muted)">No probes.</p>'
            else:
                h += '<table><thead><tr><th>IP</th><th>Count</th><th>Recent</th></tr></thead><tbody>'
                for ip, p in probes.items():
                    paths = "<br>".join(html_lib.escape(x) for x in p.get("paths", [])[-5:])
                    h += f'<tr><td><b>{html_lib.escape(ip)}</b></td><td>{p.get("count",0)}</td><td style="font-size:10px;color:var(--muted);word-break:break-all">{paths}</td></tr>'
                h += '</tbody></table>'
            h += '</div>'

        h += '</main></div>'
        h += page_bottom()
        self.send_html(h)

    def admin_perms_page(self, ip, atoken, base_path, msg=""):
        u = get_user(ip); p = u.get("perms", {}); types = set(p.get("types", []))
        all_types = ["video","audio","image","text","pdf","other"]
        labels = {"video":"Videos","audio":"Audio","image":"Images","text":"Text","pdf":"PDF","other":"Other"}
        csrf = csrf_token(atoken)

        h = page_top("Perms")
        h += '<div class="layout">'
        h += sidebar("users", base_path + f"?a={atoken}", '<a class="active" href="#">⚙️ Permissions</a>')
        h += '<main class="main">'
        h += '<div class="topbar"><button class="mobile-menu-btn" onclick="toggleSidebarCollapse()">☰</button>'
        h += f'<h1>⚙️ Permissions</h1><div class="actions"><a class="btn gray" href="{base_path}?a={atoken}">← Back</a></div></div>'
        if msg: h += f'<div class="card" style="border-color:var(--accent)">{html_lib.escape(msg)}</div>'

        h += f'''<div class="card">
          <h2>User: {html_lib.escape(ip)}</h2>
          <p style="color:var(--muted);font-size:12px;margin-bottom:12px">Status: <b>{u.get('status')}</b></p>
          <form method="POST" action="{base_path}/perms/save?a={atoken}">
            <input type="hidden" name="ip" value="{html_lib.escape(ip)}">
            <input type="hidden" name="csrf" value="{csrf}">
            <h2 style="margin-top:6px">Global</h2>
            <label style="display:block;margin:8px 0;color:var(--text);font-size:13px"><input type="checkbox" name="download" {'checked' if p.get('download') else ''}> Allow Download</label>
            <label style="display:block;margin:8px 0;color:var(--text);font-size:13px"><input type="checkbox" name="open" {'checked' if p.get('open') else ''}> Allow Open</label>
            <label style="display:block;margin:8px 0;color:var(--text);font-size:13px"><input type="checkbox" name="upload" {'checked' if p.get('upload') else ''}> Allow Upload</label>
            <h2 style="margin-top:16px">Allowed File Types</h2>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:6px">'''

        for t in all_types:
            ck = "checked" if t in types else ""
            h += f'<label style="color:var(--text);font-size:13px"><input type="checkbox" name="types" value="{t}" {ck}> {labels[t]}</label>'

        h += f'''</div>
            <div style="margin-top:18px">
              <button class="btn" type="submit">💾 Save</button>
              <a class="btn gray" href="{base_path}?a={atoken}">Cancel</a>
            </div>
          </form>
        </div></main></div>'''
        h += page_bottom()
        self.send_html(h)

    # ==================== GET ====================
    def do_GET(self):
        touch_activity()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        ip = get_client_ip(self)

        if not rate_ok(ip):
            return self.send_error(429, "Too Many Requests")
        if is_banned(ip):
            with data_lock: b = SEC["bans"].get(ip, {})
            return self.blocked_page(ip, b.get("reason", "banned"))

        admin_base = "/panel_" + ADMIN_KEY
        if path.startswith("/admin") or (path.startswith("/panel_") and not is_valid_admin_path(path)):
            register_probe(ip, path)
            return self.send_error(404, "Not found")

        if is_valid_admin_path(path):
            atoken = get_admin_token(self)
            if not atoken:
                atoken = create_session(ip, admin=True)
                return self.redirect(f"{admin_base}?a={atoken}")
            if path == admin_base + "/logout" or qs.get("logout"):
                with data_lock:
                    DATA["sessions"].pop(atoken, None); _save(DATA_FILE, DATA)
                return self.redirect("/")
            if path == admin_base + "/action":
                do = qs.get("do", [""])[0]; target = qs.get("ip", [""])[0]
                if not target: return self.redirect(f"{admin_base}?a={atoken}")
                if do == "approve":
                    update_user(target, status="approved"); clear_user_sessions(target)
                elif do == "block":
                    update_user(target, status="blocked"); clear_user_sessions(target)
                elif do == "unblock":
                    update_user(target, status="approved"); clear_user_sessions(target)
                elif do == "unban":
                    unban_ip(target); clear_user_sessions(target)
                return self.redirect(f"{admin_base}?a={atoken}")
            if path == admin_base + "/perms":
                return self.admin_perms_page(qs.get("ip", [""])[0], atoken, admin_base)
            tab = qs.get("tab", ["users"])[0]
            return self.admin_page(atoken, admin_base, tab=tab)

        if path == "/logout":
            token = get_token(self)
            if token:
                with data_lock:
                    DATA["sessions"].pop(token, None); _save(DATA_FILE, DATA)
            return self.redirect("/")

        allowed, reason = is_user_allowed(ip)
        if reason == "blocked": return self.blocked_page(ip)

        token = get_token(self)
        if not token: return self.login_page()
        if reason == "pending": return self.pending_page(ip)

        s = get_session(token)
        if s and s.get("ip") != ip:
            return self.redirect("/")

        perms = get_user(ip).get("perms", {})
        view = qs.get("view", ["list"])[0]

        if path in ("/", "/files/"):
            return self.drives_page(token, perms, view)

        rel = urllib.parse.unquote(path.lstrip("/"))
        full = rel.replace("/", os.sep)

        if os.name == "nt" and re.match(r"^[A-Za-z]:", full):
            pass
        else:
            full = os.path.join("/", full)

        if os.path.isdir(full):
            return self.list_directory(full, token, perms, view)

        if os.path.isfile(full):
            fname = os.path.basename(full)
            cat = file_category(fname)
            if cat not in set(perms.get("types", [])):
                return self.send_error(403, "No permission")
            force_dl = "dl" in qs
            if force_dl and not perms.get("download", True):
                return self.send_error(403, "Download not allowed")
            if not force_dl and not perms.get("open", True):
                return self.send_error(403, "Open not allowed")
            return self.serve_file(full, force_dl)

        register_probe(ip, path)
        self.send_error(404, "Not found")

    def serve_file(self, full, force_download=False):
        try:
            if not os.path.isfile(full):
                self.send_error(404, "File not found"); return
            size = os.path.getsize(full)
            fname = os.path.basename(full)
            ctype = get_mime(fname)
            safe_name = urllib.parse.quote(fname)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            self.security_headers()
            if force_download:
                self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{safe_name}")
            else:
                self.send_header("Content-Disposition", f"inline; filename*=UTF-8''{safe_name}")
            self.end_headers()
            with open(full, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    self.wfile.write(chunk)
        except BrokenPipeError: pass
        except Exception as e:
            try: self.send_error(500, str(e))
            except: pass

    # ==================== MULTIPART STREAMING ====================
    def _read_upload_streaming(self, boundary_bytes, content_length):
        delim = b"--" + boundary_bytes
        results = []
        buf = b""
        remaining = content_length
        state = "seek_first"
        current_fname = None
        current_tmp = None

        def flush_current():
            nonlocal current_fname, current_tmp
            if current_tmp:
                current_tmp.flush()
                current_tmp.close()
                if current_fname:
                    results.append((current_fname, current_tmp.name))
            current_fname = None
            current_tmp = None

        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk: break
            remaining -= len(chunk)
            buf += chunk

            if state == "seek_first":
                idx = buf.find(delim)
                if idx < 0:
                    if len(buf) > 1024 * 1024:
                        buf = buf[-1024:]
                    continue
                buf = buf[idx + len(delim):]
                state = "headers"
                continue

            if state == "headers":
                idx = buf.find(b"\r\n\r\n")
                if idx < 0:
                    continue
                headers_blob = buf[:idx]
                buf = buf[idx + 4:]
                headers_text = headers_blob.decode("utf-8", "ignore")
                m = re.search(r'filename="([^"]*)"', headers_text)
                raw_name = m.group(1) if m else None
                current_fname = safe_filename(raw_name) if raw_name else None

                if not current_fname:
                    state = "skip_body"
                    continue

                current_tmp = tempfile.NamedTemporaryFile(
                    delete=False, suffix=".upload", dir=CHUNKS_DIR)
                state = "body"
                continue

            if state in ("body", "skip_body"):
                marker = b"\r\n" + delim
                idx = buf.find(marker)
                if idx < 0:
                    keep = len(marker) - 1
                    if len(buf) > keep:
                        data = buf[:-keep]
                        buf = buf[-keep:]
                        if current_tmp and state == "body":
                            current_tmp.write(data)
                    continue
                data = buf[:idx]
                buf = buf[idx + len(marker):]
                if current_tmp and state == "body":
                    current_tmp.write(data)
                flush_current()
                if buf.startswith(b"--"):
                    break
                if buf.startswith(b"\r\n"):
                    buf = buf[2:]
                state = "headers"
                continue

        flush_current()
        return results

    def do_POST(self):
        touch_activity()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        ip = get_client_ip(self)

        if not rate_ok(ip): return self.send_error(429)
        if is_banned(ip): return self.blocked_page(ip, "banned")

        admin_base = "/panel_" + ADMIN_KEY

        if path == admin_base + "/perms/save":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            params = urllib.parse.parse_qs(body)
            atoken = get_admin_token(self)
            if not atoken: return self.send_error(401)
            if not check_csrf(self, atoken, params):
                return self.send_error(403, "CSRF failed")
            target = params.get("ip", [""])[0]
            if not target: return self.redirect(f"{admin_base}?a={atoken}")
            update_user(target, perms={
                "download": "download" in params,
                "open": "open" in params,
                "upload": "upload" in params,
                "types": params.get("types", []),
            })
            return self.redirect(f"{admin_base}/perms?ip={target}&a={atoken}&saved=1")

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            params = urllib.parse.parse_qs(body)
            pw = params.get("password", [""])[0]
            cleanup_sessions()
            if pw != PASSWORD:
                banned = register_failed_login(ip)
                if banned: return self.blocked_page(ip, "Too many failed attempts")
                with data_lock: a = SEC["attempts"].get(ip, {"count":0})
                left = MAX_LOGIN_ATTEMPTS - a.get("count", 0)
                return self.login_page(f"Wrong password ({left} attempts left)")
            clear_failed_login(ip)
            token = create_session(ip)
            bump_logins(ip)
            return self.redirect(f"/?t={token}")

        # ============ Multipart upload ============
        if path == "/upload":
            token = get_token(self)
            if not token:
                return self.send_error(401, "Session expired. Please login again.")
            s = get_session(token)
            if not s:
                return self.send_error(401, "Invalid session.")

            perms = get_user(s.get("ip", ip)).get("perms", {})
            if not perms.get("upload", True):
                return self.send_error(403, "Upload not allowed")

            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ctype:
                return self.send_error(400, "Expected multipart/form-data")
            m = re.search(r"boundary=(.+)$", ctype)
            if not m:
                return self.send_error(400, "No boundary")
            boundary = m.group(1).strip('"').encode()

            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return self.send_error(400, "Empty body")

            try:
                results = self._read_upload_streaming(boundary, length)
            except Exception as e:
                print("[!] Upload parse error:", e)
                return self.send_error(500, f"Parse error: {e}")

            if not results:
                return self.send_error(400, "No files parsed")

            os.makedirs(UPLOAD_DIR, exist_ok=True)
            saved = 0
            for fname, tmp_path in results:
                dest = unique_path(UPLOAD_DIR, fname)
                try:
                    shutil.move(tmp_path, dest)
                    saved += 1
                    size_mb = os.path.getsize(dest) / (1024*1024)
                    print(f"[+] Saved: {dest}  ({size_mb:.2f} MB)")
                except Exception as e:
                    print(f"[!] Cannot save {dest}: {e}")
                    try: os.remove(tmp_path)
                    except: pass

            if saved == 0:
                return self.send_error(500, "Could not save any file")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body_out = f"OK ({saved} file(s)) -> {UPLOAD_DIR}".encode("utf-8")
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        # ============ Chunked upload ============
        if path == "/upload_chunk":
            token = get_token(self)
            if not token:
                return self.send_error(401, "Session expired")
            s = get_session(token)
            if not s:
                return self.send_error(401, "Invalid session")

            perms = get_user(s.get("ip", ip)).get("perms", {})
            if not perms.get("upload", True):
                return self.send_error(403, "Upload not allowed")

            upload_id = qs.get("id", [""])[0]
            name = qs.get("name", [""])[0]
            try:
                idx = int(qs.get("idx", ["0"])[0])
                total = int(qs.get("total", ["1"])[0])
            except ValueError:
                return self.send_error(400, "Bad idx/total")

            if not upload_id or not name:
                return self.send_error(400, "Missing id or name")

            safe_name = safe_filename(name)
            if not safe_name:
                return self.send_error(400, "Invalid filename")

            os.makedirs(CHUNKS_DIR, exist_ok=True)
            tmp_file = os.path.join(CHUNKS_DIR, upload_id + ".part")

            length = int(self.headers.get("Content-Length", 0))
            if length < 0:
                return self.send_error(400, "Bad length")

            try:
                mode = "ab" if idx > 0 else "wb"
                with open(tmp_file, mode) as f:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        f.write(chunk)
            except Exception as e:
                print(f"[!] Chunk write error: {e}")
                return self.send_error(500, f"Chunk write failed: {e}")

            if idx == total - 1:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                dest = unique_path(UPLOAD_DIR, safe_name)
                try:
                    shutil.move(tmp_file, dest)
                    size_mb = os.path.getsize(dest) / (1024*1024)
                    print(f"[+] Saved: {dest}  ({size_mb:.2f} MB)")
                except Exception as e:
                    print(f"[!] Move error: {e}")
                    return self.send_error(500, f"Move failed: {e}")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body_out = f"OK chunk {idx+1}/{total}".encode()
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        self.send_error(404)

    def log_message(self, *args): pass

class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def idle_watchdog(server):
    while True:
        time.sleep(5)
        with activity_lock:
            idle = time.time() - last_activity
        if idle > IDLE_TIMEOUT:
            print(f"\n[*] Idle for {IDLE_TIMEOUT}s. Auto-shutting down...")
            server.shutdown()
            return

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    global PORT
    for _ in range(20):
        try:
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.bind(("", PORT))
            test.close()
            break
        except OSError:
            PORT += 1

    lan_ip = get_lan_ip()

    print("=" * 60)
    print("   File Server - Running")
    print("=" * 60)
    print(f"  Local   : http://127.0.0.1:{PORT}")
    print(f"  Network : http://{lan_ip}:{PORT}")
    print(f"  Admin   : http://{lan_ip}:{PORT}/panel_{ADMIN_KEY}")
    print(f"  Password: {PASSWORD}")
    print(f"  Uploads : {UPLOAD_DIR}")
    print(f"  Drives  : {', '.join(list_drives())}")
    print("=" * 60)
    print("  Press CTRL+C to stop")
    print("=" * 60)

    try:
        webbrowser.open(f"http://127.0.0.1:{PORT}")
    except Exception:
        pass

    with ReusableServer(("", PORT), Handler) as httpd:
        threading.Thread(target=idle_watchdog, args=(httpd,), daemon=True).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopped by user")

if __name__ == "__main__":
    main()