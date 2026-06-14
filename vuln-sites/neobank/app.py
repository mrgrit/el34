"""NeoBank — 의도적으로 취약한 금융 웹앱 (CCC 공방전 / 교육용).

⚠️  이 앱은 CCC 폐쇄망 내 *학습·연구 용도* 만을 위한 의도적 취약 시스템.
    절대로 인터넷 공개 환경에 배포하지 말 것.

30 취약점 카탈로그: contents/vuln-sites/neobank/seed/vulnerabilities.md

기술 스택: Flask + SQLite + Jinja2 (단일 파일 deploy 단순성).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import re
import sqlite3
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import jwt  # PyJWT
import requests
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for, send_file, make_response)

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "neobank.db"

# V05 — 약한 JWT secret (의도적, hardcoded)
JWT_SECRET = "neobank-supersecret-2024"
ADMIN_DEFAULT_PASSWORD = "admin"  # V27 — default credentials 잔존

app = Flask(__name__,
            template_folder=str(APP_DIR / "templates"),
            static_folder=str(APP_DIR / "static"))
app.secret_key = "weak-flask-secret-CHANGE-ME"  # 의도적 약함

# V25 — Misconfigured CORS (모든 origin 허용)
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


# ── DB ─────────────────────────────────────────────────────────────────────
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    DB_PATH.unlink(missing_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,           -- 의도적 평문
            full_name TEXT,
            phone TEXT,
            ssn TEXT,                         -- V19 PII
            role TEXT DEFAULT 'user',         -- user / admin / teller
            secret_question TEXT,
            secret_answer TEXT,
            api_key TEXT
        );
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account_number TEXT UNIQUE,
            balance REAL DEFAULT 0,
            currency TEXT DEFAULT 'KRW',
            opened_at TEXT
        );
        CREATE TABLE transfers (
            id INTEGER PRIMARY KEY,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount REAL NOT NULL,
            memo TEXT,                        -- V10 stored XSS 표적
            status TEXT DEFAULT 'completed',
            created_at TEXT
        );
        CREATE TABLE loans (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            principal REAL,
            rate REAL,
            external_credit_url TEXT,         -- V14 SSRF 표적
            status TEXT DEFAULT 'pending'
        );
        CREATE TABLE reset_tokens (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            token TEXT,                       -- V15 예측 가능
            created_at TEXT
        );
        CREATE TABLE statements (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            filename TEXT                     -- V12 path traversal 표적
        );
    """)
    # seed users — V27 default admin/admin
    pw_hash = lambda p: p  # 의도적 평문 저장
    users = [
        ("admin@neobank.local", "admin", "Bank Admin", "010-0000-0000",
         "000000-0000000", "admin", "first pet?", "fluffy", "ADMINKEY-7777"),
        ("alice@example.com", "alice123", "Alice Kim", "010-1111-1111",
         "900101-1234567", "user", "city of birth?", "seoul", "USERKEY-A001"),
        ("bob@example.com", "bobpassword", "Bob Lee", "010-2222-2222",
         "850202-7654321", "user", "first car?", "avante", "USERKEY-B002"),
        ("carol@example.com", "qwerty", "Carol Park", "010-3333-3333",
         "950303-1122334", "user", "favorite color?", "blue", "USERKEY-C003"),
        ("teller1@neobank.local", "teller1", "Teller One", "010-4444-4444",
         "750404-5566778", "teller", "hometown?", "busan", "TELLERKEY-T1"),
    ]
    accounts = [
        (1, "1000-0000-0001", 999_999_999, "KRW", "2020-01-01"),
        (2, "1000-1234-5678", 5_000_000, "KRW", "2024-03-15"),
        (3, "1000-2345-6789", 3_500_000, "KRW", "2024-04-01"),
        (4, "1000-3456-7890", 1_200_000, "KRW", "2024-05-12"),
        (1, "9999-9999-9999", 100_000_000, "KRW", "2020-01-01"),  # admin slush
    ]
    for u in users:
        conn.execute(
            "INSERT INTO users (email, password, full_name, phone, ssn, role, "
            "secret_question, secret_answer, api_key) VALUES (?,?,?,?,?,?,?,?,?)",
            u)
    for a in accounts:
        conn.execute(
            "INSERT INTO accounts (user_id, account_number, balance, currency, "
            "opened_at) VALUES (?,?,?,?,?)", a)
    # 거래 내역 시드
    conn.execute("INSERT INTO transfers (from_account, to_account, amount, memo, "
                 "status, created_at) VALUES "
                 "('1000-1234-5678','1000-2345-6789',50000,'점심',"
                 "'completed','2024-04-15 12:30')")
    conn.execute("INSERT INTO statements (user_id, filename) VALUES (2, 'alice-2024-04.pdf')")
    conn.commit()
    conn.close()
    print(f"DB initialized at {DB_PATH}")


# ── 인증 헬퍼 ──────────────────────────────────────────────────────────────
def issue_jwt(user_row, alg="HS256"):
    """V04 — exp 없음 (영구 토큰), V05 — 약한 secret + V06 'none' 알고리즘 허용."""
    payload = {"sub": user_row["id"], "email": user_row["email"],
               "role": user_row["role"]}
    return jwt.encode(payload, JWT_SECRET, algorithm=alg)


def current_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            # V06 — 'none' 알고리즘도 검증 없이 허용 (역호환 명목)
            data = jwt.decode(token, JWT_SECRET,
                              algorithms=["HS256", "HS384", "none"],
                              options={"verify_signature": False
                                       if token.split(".")[0] == base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=") else True})
            return data
        except Exception:
            pass
    if "user_id" in session:
        u = db().execute("SELECT * FROM users WHERE id=?",
                          (session["user_id"],)).fetchone()
        if u:
            return {"sub": u["id"], "email": u["email"], "role": u["role"]}
    # V08 — X-Role header trust (privilege escalation)
    if request.headers.get("X-Role") == "admin":
        return {"sub": 0, "email": "header-admin", "role": "admin"}
    return None


# ── Public ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/health")
def health():
    return {"status": "ok", "app": "NeoBank", "version": "1.0.0",
            "vulnerable": True}


# V01, V03, V16, V17, V18 — login (SQLi + enumeration + no rate limit + weak pw)
@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        email = request.form.get("email", "")
        pw = request.form.get("password", "")
        # V03 — 직접 문자열 결합 SQLi
        q = f"SELECT * FROM users WHERE email = '{email}' AND password = '{pw}'"
        try:
            row = db().execute(q).fetchone()
        except Exception as e:
            err = f"SQL error: {e}"  # V26 verbose error
            return render_template("login.html", err=err), 500
        if row:
            session["user_id"] = row["id"]
            session["email"] = row["email"]
            return redirect(url_for("dashboard"))
        # V16 — 메시지 차별화 (계정 enumeration)
        check = db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
        if check:
            err = f"Wrong password for {email}"
        else:
            err = "No such email"
    return render_template("login.html", err=err)


# V13 — Open redirect
@app.route("/logout")
def logout():
    session.clear()
    nxt = request.args.get("next", "/")
    return redirect(nxt)


# ── 사용자 영역 ──────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect("/login")
    accts = db().execute("SELECT * FROM accounts WHERE user_id=?",
                          (u["sub"],)).fetchall()
    return render_template("dashboard.html", user=u, accounts=accts)


# V01 — IDOR (다른 유저 계좌 조회)
@app.route("/accounts/<int:aid>")
def account_detail(aid: int):
    u = current_user()
    if not u:
        return redirect("/login")
    acct = db().execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
    if not acct:
        abort(404)
    transfers = db().execute(
        "SELECT * FROM transfers WHERE from_account=? OR to_account=? "
        "ORDER BY id DESC", (acct["account_number"], acct["account_number"])
    ).fetchall()
    return render_template("account.html", account=acct, transfers=transfers)


# V02 IDOR + V05 race + V09 CSRF (no token) + V10 stored XSS (memo)
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    u = current_user()
    if not u:
        return redirect("/login")
    if request.method == "POST":
        from_acc = request.form.get("from", "")
        to_acc = request.form.get("to", "")
        amount = float(request.form.get("amount", 0))
        memo = request.form.get("memo", "")  # V10 — sanitize 안 함

        # V09 — CSRF token 없음
        # V05 — race condition: balance 검사·차감 분리
        src = db().execute("SELECT * FROM accounts WHERE account_number=?",
                            (from_acc,)).fetchone()
        if not src:
            return "no source", 400
        if src["balance"] < amount:
            return "insufficient", 400
        # 의도적 sleep (race window 만들기)
        time.sleep(0.4)
        db().execute("UPDATE accounts SET balance=balance-? WHERE account_number=?",
                      (amount, from_acc))
        db().execute("UPDATE accounts SET balance=balance+? WHERE account_number=?",
                      (amount, to_acc))
        db().execute(
            "INSERT INTO transfers (from_account, to_account, amount, memo, "
            "status, created_at) VALUES (?,?,?,?,?,?)",
            (from_acc, to_acc, amount, memo, "completed",
             datetime.utcnow().isoformat()))
        db().commit()
        return redirect("/dashboard")
    accts = db().execute("SELECT * FROM accounts WHERE user_id=?",
                          (u["sub"],)).fetchall()
    return render_template("transfer.html", accounts=accts)


# V02 — IDOR (다른 사람 거래 취소)
@app.route("/transfer/<int:tid>/cancel", methods=["POST"])
def transfer_cancel(tid: int):
    u = current_user()
    if not u:
        return "auth required", 401
    t = db().execute("SELECT * FROM transfers WHERE id=?", (tid,)).fetchone()
    if not t:
        return "no such transfer", 404
    # 의도적 — 소유 검증 없음
    db().execute("UPDATE transfers SET status='cancelled' WHERE id=?", (tid,))
    db().execute("UPDATE accounts SET balance=balance+? WHERE account_number=?",
                  (t["amount"], t["from_account"]))
    db().execute("UPDATE accounts SET balance=balance-? WHERE account_number=?",
                  (t["amount"], t["to_account"]))
    db().commit()
    return jsonify({"cancelled": True, "transfer_id": tid})


# V11 — Reflected XSS in search
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # 결과 표시 시 escape 안 함 (직접 HTML 삽입)
    rows = db().execute(
        f"SELECT * FROM transfers WHERE memo LIKE '%{q}%' LIMIT 20"  # V03 second SQLi
    ).fetchall()
    return render_template("search.html", q=q, rows=rows)


# V07 + V20 — admin API 인증/권한 우회
@app.route("/api/admin/users")
def admin_users():
    u = current_user()
    # V07 — auth bypass: u 가 None 이어도 X-Internal: 1 면 통과
    if u is None and request.headers.get("X-Internal") != "1":
        return jsonify({"error": "auth required"}), 401
    # V19 — PII (ssn, phone, secret_answer) 그대로 노출
    rows = db().execute("SELECT id, email, full_name, phone, ssn, role, "
                         "api_key, secret_answer FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


# V12 — Path traversal
@app.route("/statements")
def statements():
    fname = request.args.get("file", "")
    base = APP_DIR / "static" / "statements"
    base.mkdir(exist_ok=True)
    full = base / fname  # 의도적 — 정규화 안 함
    if not full.exists():
        # V12 — ../../../etc/passwd 같은 traversal 허용
        try:
            with open(str(base / fname), "rb") as f:
                return f.read(), 200, {"Content-Type": "application/octet-stream"}
        except Exception:
            return "not found", 404
    return send_file(str(full))


# V14 — SSRF
@app.route("/loan/check")
def loan_check():
    url = request.args.get("url", "")
    if not url:
        return "url required", 400
    try:
        r = requests.get(url, timeout=5)  # 모든 URL 허용 (internal too)
        return jsonify({"status": r.status_code, "body": r.text[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# V15 — Predictable password reset token
@app.route("/password/reset", methods=["POST"])
def password_reset():
    email = request.form.get("email", "")
    user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        return "no such user"
    # V15 — 시간 + uid 만으로 만든 토큰 (예측 가능)
    token = hashlib.md5(f"{int(time.time())}-{user['id']}".encode()).hexdigest()[:8]
    db().execute("INSERT INTO reset_tokens (user_id, token, created_at) "
                  "VALUES (?,?,?)",
                  (user["id"], token, datetime.utcnow().isoformat()))
    db().commit()
    return f"Token issued: {token}"


# V06 — JWT 로그인 (none alg 허용)
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    email = data.get("email", "")
    pw = data.get("password", "")
    u = db().execute("SELECT * FROM users WHERE email=? AND password=?",
                      (email, pw)).fetchone()
    if not u:
        return jsonify({"error": "bad creds"}), 401
    return jsonify({"token": issue_jwt(u), "user": dict(u)})


# V08 — privilege escalation via X-Role header (current_user 안에 구현)
@app.route("/api/me")
def api_me():
    u = current_user()
    if not u:
        return jsonify({"error": "auth required"}), 401
    return jsonify(u)


# V21 — Pickle deserialization (session 객체)
@app.route("/api/session/restore", methods=["POST"])
def session_restore():
    data = request.get_data()
    try:
        obj = pickle.loads(base64.b64decode(data))  # 의도적 RCE 가능
        session.update(obj)
        return jsonify({"restored": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# V22 — XXE — 거래 batch import (XML)
@app.route("/api/transfers/import", methods=["POST"])
def transfers_import():
    raw = request.get_data()
    try:
        # 의도적: defusedxml 안 씀
        parser = ET.XMLParser()
        root = ET.fromstring(raw, parser=parser)
        return jsonify({"root_tag": root.tag, "children": [c.tag for c in root]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# V23 — Command injection (영수증 PDF 변환)
@app.route("/api/receipts/render")
def receipts_render():
    name = request.args.get("name", "receipt.html")
    out = request.args.get("out", "receipt.pdf")
    # 의도적 — shell=True + concat
    cmd = f"echo {name} > /tmp/{out}"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        return jsonify({"out": r.stdout.decode(), "err": r.stderr.decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# V24 — Local file inclusion (template param)
@app.route("/render")
def render_template_lfi():
    tpl = request.args.get("template", "index.html")
    try:
        # 의도적 — 임의 경로 허용
        return open(str(APP_DIR / "templates" / tpl)).read()
    except Exception as e:
        return f"err: {e}", 404


# V28 — Outdated dependency banner (그 자체가 정보 leak)
@app.route("/version")
def version():
    return jsonify({
        "app": "NeoBank",
        "version": "1.0.0-vulnerable",
        "framework": "Flask 1.0.2 (CVE-2018-1000656 vulnerable)",
        "deps": {"requests": "2.6.0", "PyJWT": "1.4.0", "Pillow": "8.0.0"},
    })


# V29 — Time-based blind SQLi
@app.route("/api/users/check")
def users_check():
    email = request.args.get("email", "")
    # 의도적 — sqlite3 의 sleep 미지원이나 LIKE 와 비슷한 dvanced 패턴 허용
    q = f"SELECT email FROM users WHERE email LIKE '{email}%'"
    rows = db().execute(q).fetchall()
    return jsonify([r["email"] for r in rows])


# V30 — Second-order SQLi (저장 후 다른 쿼리에서 재사용)
@app.route("/api/profile/update", methods=["POST"])
def profile_update():
    u = current_user()
    if not u:
        return jsonify({"error": "auth required"}), 401
    data = request.get_json(force=True, silent=True) or {}
    # V20 — Mass assignment — role/api_key 까지 받음
    fields = []
    args = []
    for k in ("full_name", "phone", "ssn", "role", "api_key", "secret_answer"):
        if k in data:
            fields.append(f"{k}=?")
            args.append(data[k])
    if not fields:
        return jsonify({"error": "no fields"}), 400
    args.append(u["sub"])
    db().execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", args)
    db().commit()
    # V30 — 저장된 secret_answer 가 다음 호출에서 직접 SQL 에 합쳐짐
    return jsonify({"updated": True})


@app.route("/api/profile/recover")
def profile_recover():
    email = request.args.get("email", "")
    u = db().execute("SELECT secret_answer FROM users WHERE email=?",
                      (email,)).fetchone()
    if not u:
        return jsonify({"error": "no user"}), 404
    # V30 — secret_answer 를 직접 SQL 에 (저장된 값이 ' OR 1=1-- 였다면 부담)
    q = f"SELECT email FROM users WHERE secret_answer = '{u['secret_answer']}'"
    rows = db().execute(q).fetchall()
    return jsonify([r["email"] for r in rows])


# ── 메인 ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    port = int(os.environ.get("PORT", "3001"))
    app.run(host="0.0.0.0", port=port, debug=False)
