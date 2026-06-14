"""
MediForum — 의도적 취약 의료 커뮤니티 (CCC P13 Phase 2)
================================================================
22 취약점. Stored XSS / CSRF / PII 노출 / API 인증 우회 강조.

⚠️ 교육용. 격리된 네트워크에서만 실행.

V01  Stored XSS — post body                       (A03)
V02  Stored XSS — comment                          (A03)
V03  Stored XSS — profile bio + display_name       (A03)
V04  CSRF — post create                            (A08)
V05  CSRF — comment create                         (A08)
V06  CSRF — profile update                         (A08)
V07  PII leak — /api/users 전체 (이름/email/주민번호 일부) (A02)
V08  PII leak — /api/medical-records 누구나 조회   (A01/A02)
V09  IDOR — 다른 환자 medical record               (A01)
V10  Broken API auth — /api/admin/* 인증 0          (A07)
V11  API key in URL query — log 노출               (A09/A02)
V12  Session cookie HttpOnly/Secure 미설정         (A05)
V13  CORS allow * with credentials                 (A05)
V14  Predictable session_id (counter)              (A02)
V15  Email enumeration — 가입 시 "이미 사용중" 노출 (A07)
V16  PII overshare — search 결과에 SSN/phone 포함  (A02)
V17  Mass assignment — /api/profile (role/verified) (A01)
V18  Stored XSS in DM (private message)            (A03)
V19  XSS via SVG upload (avatar)                   (A03/A09)
V20  Open redirect — /go?to=                       (A10)
V21  Verbose error — Python stack trace            (A09)
V22  Hardcoded admin token                          (A07)

Run: python app.py  (port 3003)
"""
import os, sqlite3, re, time, json, hashlib, traceback
from flask import Flask, request, jsonify, render_template, redirect, g, make_response, session
from werkzeug.utils import secure_filename  # 일부러 미사용 (V19 우회)

app = Flask(__name__)
app.secret_key = "mediforum-not-secret-2026"  # V14

DB_PATH = os.environ.get("DB_PATH", "mediforum.db")
UPLOAD = os.environ.get("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD, exist_ok=True)

ADMIN_TOKEN = "MEDIFORUM-ADMIN-2026-DEV"  # V22 hardcoded

# ----------- DB 헬퍼 -----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      role TEXT DEFAULT 'patient',  -- patient/doctor/admin
      verified INTEGER DEFAULT 0,
      bio TEXT DEFAULT '',
      ssn TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      api_key TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS posts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author_id INTEGER, title TEXT, body TEXT,
      tag TEXT DEFAULT 'general',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS comments(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER, author_id INTEGER, body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS medical_records(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id INTEGER, doctor_id INTEGER,
      diagnosis TEXT, prescription TEXT,
      visit_date TEXT
    );
    CREATE TABLE IF NOT EXISTS dms(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_id INTEGER, to_id INTEGER, body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions(
      sid TEXT PRIMARY KEY, user_id INTEGER, created_at TEXT
    );
    """)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        seed = [
            ("admin@medi.kr",   "admin123",  "관리자",       "admin",   1, "MediForum 관리자",        "800101-1******", "010-0000-0000", "ak-admin-1111"),
            ("dr.kim@medi.kr",  "doctor123", "김의사 (내과)","doctor",  1, "내과 전문의 · 진료 12년", "750515-1******", "010-1111-1111", "ak-doc-2222"),
            ("dr.lee@medi.kr",  "doctor123", "이의사 (외과)","doctor",  1, "외과 전문의 · 외상 외과", "780303-2******", "010-2222-2222", "ak-doc-3333"),
            ("alice@user.kr",   "alice123",  "앨리스",       "patient", 1, "당뇨 관리 중",            "920722-2******", "010-3333-3333", "ak-pat-4444"),
            ("bob@user.kr",     "bob123",    "밥",           "patient", 0, "어깨 통증",               "880909-1******", "010-4444-4444", "ak-pat-5555"),
            ("carol@user.kr",   "carol123",  "캐롤",         "patient", 1, "혈압 관리",               "950611-2******", "010-5555-5555", "ak-pat-6666"),
        ]
        cur.executemany("INSERT INTO users(email,password,display_name,role,verified,bio,ssn,phone,api_key) VALUES(?,?,?,?,?,?,?,?,?)", seed)

        cur.executemany("INSERT INTO posts(author_id,title,body,tag) VALUES(?,?,?,?)", [
            (2, "감기 예방법 5가지", "손 자주 씻기, 충분한 수면 등...", "tip"),
            (3, "어깨 통증 자가 진단", "팔을 들 때 통증이 있다면...", "tip"),
            (4, "당뇨 식단 공유", "현미, 견과류 추천드려요!", "share"),
            (1, "[공지] 의료정보 무단 전송 금지", "본 포럼은 익명입니다.", "notice"),
        ])
        cur.executemany("INSERT INTO comments(post_id,author_id,body) VALUES(?,?,?)", [
            (1,4,"감사합니다 도움돼요"),
            (1,5,"좋은 글이네요"),
            (3,2,"식단 좋네요. 운동도 같이 추천드립니다."),
        ])
        cur.executemany("INSERT INTO medical_records(patient_id,doctor_id,diagnosis,prescription,visit_date) VALUES(?,?,?,?,?)", [
            (4,2,"제2형 당뇨 의심","메트포민 500mg 1일 2회","2026-04-10"),
            (5,3,"좌측 회전근개 부분 파열","조영제 MRI 권고, NSAIDs 처방","2026-04-12"),
            (6,2,"본태성 고혈압","암로디핀 5mg 1일 1회","2026-04-15"),
            (4,3,"발목 염좌 (자전거)","압박 + 부목, 7일 후 재진","2026-04-18"),
        ])
        cur.executemany("INSERT INTO dms(from_id,to_id,body) VALUES(?,?,?)", [
            (4,2,"선생님 처방 감사합니다."),
            (2,4,"증상 변화 있으면 바로 알려주세요."),
        ])
    con.commit(); con.close()

# ----------- 세션 (V14 predictable) -----------
_SESSION_COUNTER = {"n": 1000}
def issue_session(uid):
    _SESSION_COUNTER["n"] += 1
    sid = f"sess-{_SESSION_COUNTER['n']}"  # V14
    cur = db().cursor()
    cur.execute("INSERT INTO sessions(sid,user_id,created_at) VALUES(?,?,datetime('now'))", (sid, uid))
    db().commit()
    return sid

def current_user():
    sid = request.cookies.get("MFSID")
    # V22 admin token 우회
    if request.headers.get("X-Admin-Token") == ADMIN_TOKEN:
        cur = db().cursor()
        cur.execute("SELECT * FROM users WHERE role='admin' LIMIT 1")
        return cur.fetchone()
    if not sid: return None
    cur = db().cursor()
    cur.execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.sid=?", (sid,))
    return cur.fetchone()

# ----------- 보안 헤더 (V12/V13 불완전) -----------
@app.after_request
def headers(resp):
    resp.headers["Server"] = "nginx/1.18.0"
    # V13 CORS
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    return resp

# ----------- 페이지 -----------
@app.route("/")
def index():
    cur = db().cursor()
    cur.execute("""SELECT p.*, u.display_name, (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS cmt
                   FROM posts p LEFT JOIN users u ON u.id=p.author_id ORDER BY p.id DESC LIMIT 30""")
    posts = cur.fetchall()
    return render_template("index.html", posts=posts, me=current_user())

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    email = request.form.get("email","").strip()
    pw = request.form.get("password","").strip()
    cur = db().cursor()
    cur.execute("SELECT id,password FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row or row["password"] != pw:
        return render_template("login.html", error="이메일/비밀번호 확인"), 401
    sid = issue_session(row["id"])
    resp = make_response(redirect("/"))
    # V12: HttpOnly/Secure 미설정
    resp.set_cookie("MFSID", sid)
    return resp

@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("MFSID", "", expires=0)
    return resp

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    email = request.form.get("email","").strip()
    pw = request.form.get("password","x")
    name = request.form.get("display_name","익명")
    cur = db().cursor()
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    # V15 email enumeration
    if cur.fetchone():
        return render_template("register.html", error=f"{email} 는 이미 사용 중입니다."), 409
    api_key = "ak-" + hashlib.md5(email.encode()).hexdigest()[:10]
    cur.execute("INSERT INTO users(email,password,display_name,role,api_key) VALUES(?,?,?,'patient',?)",
                (email, pw, name, api_key))
    db().commit()
    return redirect("/login")

# ----------- Posts (V01 stored XSS) -----------
@app.route("/posts/new", methods=["GET","POST"])
def post_new():
    me = current_user()
    if not me: return redirect("/login")
    if request.method == "GET":
        return render_template("post_new.html", me=me)
    # V04 CSRF: 토큰 0
    title = request.form.get("title","")
    body  = request.form.get("body","")  # V01 raw 저장
    tag   = request.form.get("tag","general")
    cur = db().cursor()
    cur.execute("INSERT INTO posts(author_id,title,body,tag) VALUES(?,?,?,?)",
                (me["id"], title, body, tag))
    db().commit()
    return redirect(f"/posts/{cur.lastrowid}")

@app.route("/posts/<int:pid>")
def post_detail(pid):
    cur = db().cursor()
    cur.execute("SELECT p.*, u.display_name FROM posts p LEFT JOIN users u ON u.id=p.author_id WHERE p.id=?", (pid,))
    p = cur.fetchone()
    if not p: return "not found", 404
    cur.execute("""SELECT c.*, u.display_name FROM comments c LEFT JOIN users u ON u.id=c.author_id
                   WHERE c.post_id=? ORDER BY c.id""", (pid,))
    cmts = cur.fetchall()
    return render_template("post_detail.html", p=p, cmts=cmts, me=current_user())

@app.route("/posts/<int:pid>/comment", methods=["POST"])
def comment_new(pid):
    me = current_user()
    if not me: return redirect("/login")
    body = request.form.get("body","")  # V02 stored XSS
    # V05 CSRF
    cur = db().cursor()
    cur.execute("INSERT INTO comments(post_id,author_id,body) VALUES(?,?,?)", (pid, me["id"], body))
    db().commit()
    return redirect(f"/posts/{pid}")

# ----------- Profile (V03/V06 + V17 mass assign) -----------
@app.route("/profile/<int:uid>")
def profile(uid):
    cur = db().cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    u = cur.fetchone()
    if not u: return "not found", 404
    return render_template("profile.html", u=u, me=current_user())

@app.route("/profile/edit", methods=["GET","POST"])
def profile_edit():
    me = current_user()
    if not me: return redirect("/login")
    if request.method == "GET":
        return render_template("profile_edit.html", me=me)
    # V06 CSRF + V17 mass assign — form 필드 그대로 update
    fields = ["display_name","bio","phone","ssn","email","role","verified","api_key"]
    sets, vals = [], []
    for f in fields:
        if f in request.form:
            sets.append(f"{f}=?"); vals.append(request.form.get(f))
    if sets:
        vals.append(me["id"])
        cur = db().cursor()
        cur.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
        db().commit()
    return redirect(f"/profile/{me['id']}")

# ----------- Avatar upload (V19 SVG XSS) -----------
@app.route("/profile/avatar", methods=["POST"])
def avatar():
    me = current_user()
    if not me: return redirect("/login")
    f = request.files.get("file")
    if not f: return "no file", 400
    # V19: 확장자 검증 0, secure_filename 미사용
    fname = f"u{me['id']}_{int(time.time())}_{f.filename}"
    f.save(os.path.join(UPLOAD, fname))
    return jsonify({"ok": True, "url": f"/uploads/{fname}"})

@app.route("/uploads/<path:fn>")
def uploads(fn):
    # 직접 파일 반환 (Content-Type 추론)
    safe = os.path.join(UPLOAD, fn)
    if not os.path.isfile(safe):
        return "not found", 404
    with open(safe, "rb") as fp: data = fp.read()
    ext = fn.rsplit(".",1)[-1].lower()
    ct = {"png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg",
          "gif":"image/gif","svg":"image/svg+xml"}.get(ext,"application/octet-stream")
    resp = make_response(data); resp.headers["Content-Type"] = ct
    return resp

# ----------- DM (V18 stored XSS in private msg) -----------
@app.route("/dm")
def dm_inbox():
    me = current_user()
    if not me: return redirect("/login")
    cur = db().cursor()
    cur.execute("""SELECT d.*, u.display_name AS from_name FROM dms d LEFT JOIN users u ON u.id=d.from_id
                   WHERE d.to_id=? ORDER BY d.id DESC""", (me["id"],))
    return render_template("dm.html", msgs=cur.fetchall(), me=me)

@app.route("/dm/send", methods=["POST"])
def dm_send():
    me = current_user()
    if not me: return redirect("/login")
    to = int(request.form.get("to_id","0"))
    body = request.form.get("body","")  # V18 raw 저장
    cur = db().cursor()
    cur.execute("INSERT INTO dms(from_id,to_id,body) VALUES(?,?,?)", (me["id"], to, body))
    db().commit()
    return redirect("/dm")

# ----------- Search (V16 PII overshare) -----------
@app.route("/search")
def search():
    q = request.args.get("q","").strip()
    cur = db().cursor()
    if q:
        # V16: SSN/phone 포함 결과
        cur.execute("""SELECT id,email,display_name,role,bio,ssn,phone,api_key
                       FROM users WHERE display_name LIKE ? OR email LIKE ? OR bio LIKE ?""",
                    (f"%{q}%", f"%{q}%", f"%{q}%"))
        results = [dict(r) for r in cur.fetchall()]
    else:
        results = []
    return render_template("search.html", q=q, results=results, me=current_user())

# ----------- Open redirect (V20) -----------
@app.route("/go")
def go():
    to = request.args.get("to","/")
    return redirect(to)  # V20: 검증 0

# ----------- API: PII / IDOR / Broken auth -----------
@app.route("/api/users")
def api_users():
    # V07: 인증 없이 전체 PII (email/ssn 마스킹)/phone/api_key 노출
    cur = db().cursor()
    cur.execute("SELECT id,email,display_name,role,verified,phone,ssn,api_key,bio FROM users")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/users/<int:uid>")
def api_user_one(uid):
    # V11: api_key 를 query 로 받아도 통과
    key = request.args.get("api_key") or request.headers.get("X-API-Key")
    cur = db().cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    u = cur.fetchone()
    if not u: return jsonify({"error":"not found"}), 404
    if key and key != u["api_key"]:
        # 그래도 IDOR 가능: api_key 만 맞추면 자기 것 아니어도 ok (V09 IDOR 변형)
        cur.execute("SELECT id FROM users WHERE api_key=?", (key,))
        if not cur.fetchone():
            return jsonify({"error":"bad key"}), 401
    return jsonify(dict(u))

@app.route("/api/medical-records")
def api_med_all():
    # V08 PII leak — 전체 환자 기록 인증 0
    cur = db().cursor()
    cur.execute("""SELECT m.*, p.display_name AS patient_name, p.ssn AS patient_ssn,
                          d.display_name AS doctor_name FROM medical_records m
                   LEFT JOIN users p ON p.id=m.patient_id
                   LEFT JOIN users d ON d.id=m.doctor_id ORDER BY m.id DESC""")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/medical-records/<int:rid>")
def api_med_one(rid):
    # V09 IDOR: 어떤 사용자도 다른 사람 기록 조회
    me = current_user()
    cur = db().cursor()
    cur.execute("SELECT * FROM medical_records WHERE id=?", (rid,))
    r = cur.fetchone()
    if not r: return jsonify({"error":"not found"}), 404
    # 의도적으로 patient_id 검증 0
    return jsonify(dict(r))

@app.route("/api/admin/users")
def api_admin_users():
    # V10 broken admin auth — 인증 0
    cur = db().cursor()
    cur.execute("SELECT * FROM users")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/admin/dms")
def api_admin_dms():
    # V10: 모든 DM 인증 0 — privacy leak
    cur = db().cursor()
    cur.execute("SELECT * FROM dms ORDER BY id DESC")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/profile", methods=["POST"])
def api_profile_update():
    # V17 mass assignment via JSON
    me = current_user()
    if not me:
        # V22 admin token 통과
        if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
            return jsonify({"error":"auth"}), 401
        me_id = 1
    else:
        me_id = me["id"]
    payload = request.get_json(silent=True) or {}
    fields = ["display_name","bio","phone","ssn","email","role","verified","api_key"]
    sets, vals = [], []
    for f in fields:
        if f in payload:
            sets.append(f"{f}=?"); vals.append(payload[f])
    if not sets:
        return jsonify({"error":"no fields"}), 400
    vals.append(me_id)
    cur = db().cursor()
    cur.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
    db().commit()
    cur.execute("SELECT * FROM users WHERE id=?", (me_id,))
    return jsonify(dict(cur.fetchone()))

# ----------- Verbose error (V21) -----------
@app.errorhandler(500)
def err500(e):
    tb = traceback.format_exc()
    return f"<h1>500 Internal Error</h1><pre>{tb}</pre>", 500

@app.route("/api/debug/echo")
def api_debug_echo():
    # V21: 의도적 raise — request 파라미터 stack에 노출
    raise RuntimeError(f"debug echo: q={request.args.get('q','')}")

# ----------- 헬스 -----------
@app.route("/_health")
def health():
    return {"ok": True, "service": "mediforum", "vulns": 22}

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT","3003"))
    print(f"[mediforum] listening on :{port} (22 vulns, theme=medical)")
    app.run(host="0.0.0.0", port=port, debug=False)
