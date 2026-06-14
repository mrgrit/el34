"""
AdminConsole — 의도적 취약 DevOps 관리자 패널 (CCC P13 Phase 2)
================================================================
28 취약점. SSRF / RCE / 명령 주입 / 비밀번호 분실 흐름 강조.

⚠️ 교육용. 격리된 네트워크에서만 실행. 절대 외부 노출 금지.

V01  Cmd injection — /tools/ping (host)              (A03)
V02  Cmd injection — /tools/dig (domain)             (A03)
V03  Cmd injection — /tools/whois                     (A03)
V04  SSRF — /tools/fetch?url=                          (A10)
V05  SSRF — webhook test (cloud metadata)              (A10)
V06  SSRF — git clone any URL                          (A10/A03)
V07  RCE — eval in /tools/calc?expr=                   (A03)
V08  RCE — pickle deserialization /api/jobs/import     (A08)
V09  Path Traversal — /files/read?path=                (A05)
V10  LFI → RCE — log viewer + log poisoning            (A05/A03)
V11  Weak password reset — predictable token           (A07)
V12  Reset token via email enumeration                 (A07)
V13  Reset token doesn't expire                        (A07)
V14  Default admin admin/admin                         (A07)
V15  JWT alg=none accepted                             (A02)
V16  IDOR — /api/secrets/<id>                          (A01)
V17  Insecure deserialization — yaml.load              (A08)
V18  Hardcoded shared secret                           (A02)
V19  Verbose error — stack trace + env                 (A09)
V20  Missing auth — /api/users/list                    (A07)
V21  CSRF — POST 보호 0                                 (A08)
V22  XSS — admin notes                                 (A03)
V23  Mass assignment — /api/users/update               (A01)
V24  Weak file upload — RCE via .py                    (A08)
V25  XXE — POST /api/import.xml                         (A05)
V26  HTTP smuggling header (CL+TE 통과)                (A05)
V27  Open redirect — /sso/return?next=                 (A10)
V28  Sensitive data in URL — /api/console?token=       (A09/A02)

Run: python app.py  (port 3004)
"""
import os, sqlite3, json, time, hashlib, traceback, base64, pickle, subprocess, hmac
import urllib.request, urllib.error, xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, render_template, redirect, g, make_response

try:
    import yaml  # V17
except Exception:
    yaml = None

app = Flask(__name__)
app.secret_key = "ADMINCONSOLE-INSECURE-2026"  # V18

DB_PATH = os.environ.get("DB_PATH", "adminconsole.db")
UPLOAD = os.environ.get("UPLOAD_DIR", "uploads")
LOGDIR = os.environ.get("LOG_DIR", "logs")
os.makedirs(UPLOAD, exist_ok=True); os.makedirs(LOGDIR, exist_ok=True)

SHARED_SECRET = "ac-shared-secret-2026"  # V18 hardcoded

# ----------- DB -----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE, password TEXT,
      email TEXT, role TEXT DEFAULT 'operator',
      api_token TEXT, notes TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS reset_tokens(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, token TEXT, created_at INTEGER, used INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS secrets(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER, kind TEXT, name TEXT, value TEXT
    );
    CREATE TABLE IF NOT EXISTS jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, status TEXT, created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, user_id INTEGER, created_at INTEGER);
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO users(username,password,email,role,api_token,notes) VALUES(?,?,?,?,?,?)", [
            ("admin",  "admin",      "admin@ac.local",   "admin",    "tok-admin-1111",  "default account"),
            ("ops1",   "ops1pass",   "ops1@ac.local",    "operator", "tok-ops-2222",    "L1 oncall"),
            ("dev",    "devpass",    "dev@ac.local",     "developer","tok-dev-3333",    "ci/cd readonly"),
            ("auditor","auditorpw",  "auditor@ac.local", "auditor",  "tok-audit-4444",  "compliance"),
        ])
        cur.executemany("INSERT INTO secrets(owner_id,kind,name,value) VALUES(?,?,?,?)", [
            (1, "aws_key", "prod-aws", "AKIA1234567890PROD/secret=verysecret"),
            (1, "db_url",  "prod-db",  "postgres://root:rootpw@10.10.10.5:5432/prod"),
            (2, "ssh_key", "ops-bastion", "-----BEGIN OPENSSH PRIVATE KEY-----..."),
            (3, "git_token", "github-ci", "ghp_devCIToken_xxxxxxxxx"),
        ])
        cur.executemany("INSERT INTO jobs(title,status,created_at) VALUES(?,?,?)", [
            ("nightly-backup",   "ok",     int(time.time())-86400),
            ("rotate-iam-keys",  "queued", int(time.time())-3600),
            ("vuln-scan-prod",   "running",int(time.time())-300),
        ])
    con.commit(); con.close()

# ----------- Session -----------
def issue_session(uid):
    sid = hashlib.md5(f"{uid}-{time.time()}".encode()).hexdigest()
    cur = db().cursor()
    cur.execute("INSERT INTO sessions(sid,user_id,created_at) VALUES(?,?,?)", (sid, uid, int(time.time())))
    db().commit(); return sid

def current_user():
    sid = request.cookies.get("ACSID")
    # V15 JWT alg=none
    auth = request.headers.get("Authorization","")
    if auth.startswith("Bearer "):
        tok = auth[7:]
        try:
            parts = tok.split(".")
            if len(parts) == 3:
                hdr = json.loads(base64.urlsafe_b64decode(parts[0]+"==").decode())
                payload = json.loads(base64.urlsafe_b64decode(parts[1]+"==").decode())
                if hdr.get("alg","").lower() == "none":  # V15
                    cur = db().cursor()
                    cur.execute("SELECT * FROM users WHERE username=?", (payload.get("sub",""),))
                    r = cur.fetchone()
                    if r: return r
        except Exception:
            pass
    if not sid: return None
    cur = db().cursor()
    cur.execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.sid=?", (sid,))
    return cur.fetchone()

def require_admin():
    u = current_user()
    if not u or u["role"] != "admin":
        return None
    return u

# ----------- Headers -----------
@app.after_request
def hdr(resp):
    resp.headers["Server"] = "Werkzeug/2.3 (AdminConsole)"
    resp.headers["X-Powered-By"] = "Flask"
    # V26 HTTP smuggling 표면: Transfer-Encoding+Content-Length 모두 허용 (실제 차단 0)
    return resp

# ----------- 페이지 -----------
@app.route("/")
def index():
    cur = db().cursor()
    cur.execute("SELECT id,username,role,email FROM users")
    users = cur.fetchall()
    cur.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 10")
    jobs = cur.fetchall()
    return render_template("index.html", me=current_user(), users=users, jobs=jobs)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET": return render_template("login.html")
    u = request.form.get("username",""); p = request.form.get("password","")
    cur = db().cursor()
    cur.execute("SELECT id FROM users WHERE username=? AND password=?", (u,p))
    r = cur.fetchone()
    if not r:
        return render_template("login.html", error="login failed"), 401
    sid = issue_session(r["id"])
    resp = make_response(redirect("/"))
    resp.set_cookie("ACSID", sid)  # V12-style 비-HttpOnly
    return resp

@app.route("/logout")
def logout():
    resp = make_response(redirect("/")); resp.set_cookie("ACSID","",expires=0); return resp

# ----------- 비밀번호 분실 (V11/V12/V13) -----------
@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method == "GET": return render_template("forgot.html")
    email = request.form.get("email","")
    cur = db().cursor()
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    r = cur.fetchone()
    if not r:
        # V12 enumeration
        return render_template("forgot.html", error=f"{email} 등록되지 않음"), 404
    # V11: 토큰 = md5(email + day) 예측 가능
    token = hashlib.md5((email + time.strftime("%Y%m%d")).encode()).hexdigest()[:12]
    cur.execute("INSERT INTO reset_tokens(user_id,token,created_at) VALUES(?,?,?)",
                (r["id"], token, int(time.time())))
    db().commit()
    # V13: 만료 0
    return render_template("forgot.html", message=f"리셋 링크 발송: /reset?token={token}")

@app.route("/reset", methods=["GET","POST"])
def reset():
    tok = request.values.get("token","")
    cur = db().cursor()
    cur.execute("SELECT * FROM reset_tokens WHERE token=? AND used=0", (tok,))
    rt = cur.fetchone()
    if not rt:
        return "invalid token", 400
    if request.method == "GET":
        return render_template("reset.html", token=tok)
    new_pw = request.form.get("password","x")
    cur.execute("UPDATE users SET password=? WHERE id=?", (new_pw, rt["user_id"]))
    cur.execute("UPDATE reset_tokens SET used=1 WHERE id=?", (rt["id"],))
    db().commit()
    return redirect("/login")

# ----------- Tools (V01-V04 cmd inject + SSRF) -----------
@app.route("/tools", methods=["GET","POST"])
def tools():
    me = current_user()
    if not me: return redirect("/login")
    out = ""; tool = ""
    if request.method == "POST":
        tool = request.form.get("tool","")
        target = request.form.get("target","")
        if tool == "ping":
            # V01 cmd inject
            out = subprocess.getoutput(f"ping -c 2 -W 1 {target}")
        elif tool == "dig":
            # V02
            out = subprocess.getoutput(f"dig +short {target}")
        elif tool == "whois":
            # V03
            out = subprocess.getoutput(f"whois {target} 2>&1 | head -40")
        elif tool == "fetch":
            # V04 SSRF
            try:
                with urllib.request.urlopen(target, timeout=5) as r:
                    out = r.read(8192).decode("utf-8","replace")
            except Exception as e:
                out = f"err: {e}"
        elif tool == "calc":
            # V07 RCE eval
            try:
                out = str(eval(target))  # nosec
            except Exception as e:
                out = f"err: {e}"
        elif tool == "git_clone":
            # V06 SSRF + RCE 잠재성 (--upload-pack 등 git option injection)
            out = subprocess.getoutput(f"timeout 10 git ls-remote {target} 2>&1 | head -10")
    return render_template("tools.html", me=me, out=out, tool=tool)

@app.route("/api/webhook/test")
def webhook_test():
    # V05 SSRF — cloud metadata 가능
    url = request.args.get("url","")
    if not url: return jsonify({"error":"no url"}), 400
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = r.read(4096)
        return jsonify({"status":"ok","preview": data.decode("utf-8","replace")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------- Files (V09 LFI / V10 log poisoning) -----------
@app.route("/files/read")
def files_read():
    me = current_user()
    if not me: return redirect("/login")
    p = request.args.get("path","")
    # V09 path traversal
    if not p: return "no path", 400
    try:
        with open(p, "rb") as f: data = f.read(8192)
        resp = make_response(data); resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        return resp
    except Exception as e:
        return f"err: {e}", 500

@app.route("/logs/view")
def logs_view():
    me = current_user()
    if not me: return redirect("/login")
    fn = request.args.get("file","app.log")
    # V10: log viewer + log_poisoning 가능 (UA/path 등 raw 기록 + LFI 결합)
    full = os.path.join(LOGDIR, fn)
    try:
        with open(full, "r", errors="replace") as f: data = f.read()[-8000:]
        # 의도적으로 raw 출력 (PHP-like log poisoning 데모)
        return f"<pre>{data}</pre>"
    except Exception as e:
        return f"err: {e}", 500

@app.before_request
def _log_request():
    # V10 보조: User-Agent + path raw 기록 → LFI 결합으로 LFI→RCE 시연 가능
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {request.method} {request.path} UA={request.headers.get('User-Agent','')}\n"
    try:
        with open(os.path.join(LOGDIR, "app.log"), "a") as f: f.write(line)
    except Exception: pass

# ----------- Jobs (V08 pickle / V17 yaml / V25 xxe) -----------
@app.route("/api/jobs/import", methods=["POST"])
def jobs_import():
    # V08 pickle
    body = request.get_data()
    try:
        obj = pickle.loads(body)  # nosec
        return jsonify({"loaded": str(type(obj).__name__), "preview": str(obj)[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/jobs/import.yaml", methods=["POST"])
def jobs_import_yaml():
    if not yaml: return jsonify({"error":"yaml not installed"}), 500
    body = request.get_data().decode("utf-8","replace")
    try:
        # V17 yaml.load (full loader 동작) — pyyaml 6+ 에선 unsafe_load 명시
        obj = yaml.unsafe_load(body) if hasattr(yaml,"unsafe_load") else yaml.load(body, Loader=yaml.Loader)
        return jsonify({"ok": True, "type": str(type(obj).__name__)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/import.xml", methods=["POST"])
def import_xml():
    # V25 XXE
    body = request.get_data()
    try:
        parser = ET.XMLParser()
        root = ET.fromstring(body, parser=parser)
        return jsonify({"tag": root.tag, "text": (root.text or "")[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------- Files upload (V24 .py upload) -----------
@app.route("/upload", methods=["POST"])
def upload():
    me = current_user()
    if not me: return jsonify({"error":"auth"}), 401
    f = request.files.get("file")
    if not f: return jsonify({"error":"no file"}),400
    fname = f.filename  # V24 검증 0
    f.save(os.path.join(UPLOAD, fname))
    return jsonify({"ok":True,"path":f"uploads/{fname}"})

# ----------- API (V16/V20/V23) -----------
@app.route("/api/users/list")
def api_users_list():
    # V20 missing auth
    cur = db().cursor()
    cur.execute("SELECT id,username,email,role,api_token,notes FROM users")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/users/update", methods=["POST"])
def api_users_update():
    # V21 CSRF + V23 mass assign
    me = current_user()
    if not me: return jsonify({"error":"auth"}),401
    payload = request.get_json(silent=True) or {}
    fields = ["username","password","email","role","api_token","notes"]
    sets, vals = [], []
    for f in fields:
        if f in payload:
            sets.append(f"{f}=?"); vals.append(payload[f])
    if not sets: return jsonify({"error":"no fields"}),400
    target_id = payload.get("id", me["id"])  # 다른 사람도 대상 가능 (BAC)
    vals.append(target_id)
    cur = db().cursor()
    cur.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
    db().commit()
    cur.execute("SELECT * FROM users WHERE id=?", (target_id,))
    return jsonify(dict(cur.fetchone()))

@app.route("/api/secrets/<int:sid>")
def api_secret(sid):
    # V16 IDOR
    cur = db().cursor()
    cur.execute("SELECT * FROM secrets WHERE id=?", (sid,))
    r = cur.fetchone()
    if not r: return jsonify({"error":"not found"}),404
    return jsonify(dict(r))

# ----------- Notes (V22 XSS) -----------
@app.route("/notes", methods=["GET","POST"])
def notes():
    me = current_user()
    if not me: return redirect("/login")
    if request.method == "POST":
        # V22 stored XSS in admin notes
        cur = db().cursor()
        cur.execute("UPDATE users SET notes=? WHERE id=?", (request.form.get("notes",""), me["id"]))
        db().commit()
    cur = db().cursor()
    cur.execute("SELECT id,username,notes FROM users")
    return render_template("notes.html", me=me, all_notes=cur.fetchall())

# ----------- SSO (V27 open redirect, V28 sensitive token in URL) -----------
@app.route("/sso/return")
def sso_return():
    # V27 open redirect
    return redirect(request.args.get("next","/"))

@app.route("/api/console")
def api_console():
    # V28 sensitive token in URL query (logged everywhere)
    tok = request.args.get("token","")
    me_token = (current_user() or {}).get("api_token") if current_user() else None
    if tok and me_token and tok == me_token:
        return jsonify({"console":"granted","cmd_history":["ls /","whoami"]})
    return jsonify({"console":"denied"}), 403

# ----------- Verbose error (V19) -----------
@app.errorhandler(500)
def err500(e):
    tb = traceback.format_exc()
    return f"<h1>500</h1><pre>{tb}\n\nENV(safe subset):\n{json.dumps({k:v for k,v in os.environ.items() if k.upper() in ('PATH','HOME','USER','SHELL','PORT')}, indent=2)}</pre>", 500

@app.route("/api/debug/raise")
def debug_raise():
    raise RuntimeError("debug raised by " + request.args.get("who","anon"))

# ----------- 헬스 -----------
@app.route("/_health")
def health():
    return {"ok": True, "service": "adminconsole", "vulns": 28}

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT","3004"))
    print(f"[adminconsole] :{port} (28 vulns, theme=devops)")
    app.run(host="0.0.0.0", port=port, debug=False)
