"""GovPortal — 의도적으로 취약한 정부 민원 시스템 (CCC 공방전 / 교육용).

⚠️  CCC 폐쇄망 학습 전용. 인터넷 노출 절대 금지.

25 취약점 카탈로그: contents/vuln-sites/govportal/seed/vulnerabilities.md
강조 영역: SAML/JWT 우회 · 파일 업로드 · 권한 상승 · CSRF · authority chain abuse
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import jwt
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for, make_response)

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "govportal.db"
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

JWT_SECRET = "gov-shared-secret-2023"  # V05 — 약한 hardcoded
SAML_HMAC_KEY = "gov-saml-key"          # V03 — SAML 서명 검증 약함
DEFAULT_ADMIN_PIN = "1234"              # V21 — default PIN

app = Flask(__name__,
            template_folder=str(APP_DIR / "templates"),
            static_folder=str(APP_DIR / "static"))
app.secret_key = "gov-flask-weak"


# V25 — 응답 헤더 누락 (X-Frame-Options 등 보안 헤더 0)
@app.after_request
def headers(resp):
    # 의도적 — 보안 헤더 안 붙임
    resp.headers["Server"] = "GovPortal/1.0 (Apache/2.4.49 - CVE-2021-41773 vulnerable)"  # V24 banner (ASCII only)
    return resp


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
        CREATE TABLE citizens (
            id INTEGER PRIMARY KEY,
            ssn TEXT UNIQUE,                   -- 주민번호 (V18 PII)
            email TEXT,
            full_name TEXT,
            phone TEXT,
            password TEXT,                     -- 평문
            role TEXT DEFAULT 'citizen',       -- citizen / clerk / officer / admin
            authority_level INTEGER DEFAULT 1, -- V08 권한 레벨 trust
            address TEXT
        );
        CREATE TABLE applications (
            id INTEGER PRIMARY KEY,
            citizen_id INTEGER,
            application_type TEXT,             -- birth_cert / residence / business
            status TEXT DEFAULT 'pending',     -- pending / approved / rejected
            content TEXT,                      -- V11 stored XSS 표적
            attached_file TEXT,
            submitted_at TEXT,
            approved_by INTEGER
        );
        CREATE TABLE certificates (
            id INTEGER PRIMARY KEY,
            citizen_id INTEGER,
            cert_type TEXT,
            cert_number TEXT,                  -- V07 예측 가능
            issued_at TEXT,
            valid_until TEXT,
            file_path TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT,
            action TEXT,
            target TEXT,
            timestamp TEXT,
            ip TEXT
        );
        CREATE TABLE saml_sessions (
            id INTEGER PRIMARY KEY,
            citizen_id INTEGER,
            saml_token TEXT,                   -- V03 우회 표적
            issuer TEXT,
            expires_at TEXT
        );
    """)
    citizens = [
        ("000000-0000000", "admin@gov.local", "System Admin", "010-0000-0000",
         "admin", "admin", 99, "정부청사 1층"),
        ("900101-1234567", "kim@gmail.com", "김철수", "010-1111-1111",
         "kim2024", "citizen", 1, "서울특별시 종로구 사직로 11"),
        ("850202-7654321", "lee@naver.com", "이영희", "010-2222-2222",
         "password", "citizen", 1, "부산광역시 해운대구 우동 1234"),
        ("750303-1112223", "park@daum.net", "박민수", "010-3333-3333",
         "minsu1234", "clerk", 5, "서울특별시 중구 명동 56"),
        ("650404-2223334", "jung@example.com", "정수정", "010-4444-4444",
         "jung01", "officer", 7, "대전광역시 서구 둔산동 89"),
    ]
    for c in citizens:
        conn.execute(
            "INSERT INTO citizens (ssn, email, full_name, phone, password, "
            "role, authority_level, address) VALUES (?,?,?,?,?,?,?,?)", c)
    apps = [
        (2, "birth_cert", "approved", "출생증명서 신청", None, "2024-04-10", 5),
        (3, "residence", "pending", "주민등록 등본", None, "2024-04-12", None),
        (2, "business", "pending", "<script>alert('XSS')</script>사업자등록", None,
         "2024-04-15", None),
    ]
    for a in apps:
        conn.execute(
            "INSERT INTO applications (citizen_id, application_type, status, "
            "content, attached_file, submitted_at, approved_by) "
            "VALUES (?,?,?,?,?,?,?)", a)
    # V07 — 예측 가능한 cert_number (citizen_id + date)
    conn.execute("INSERT INTO certificates (citizen_id, cert_type, cert_number, "
                 "issued_at, valid_until) VALUES (2, 'birth_cert', "
                 "'CERT-2024-0002-001', '2024-04-10', '2025-04-10')")
    conn.commit()
    conn.close()
    print(f"DB initialized at {DB_PATH}")


# ── 인증 ───────────────────────────────────────────────────────────────────
def issue_jwt(c):
    payload = {"sub": c["id"], "ssn": c["ssn"], "role": c["role"],
               "level": c["authority_level"]}
    # V05 — 약한 secret + V06 알고리즘 다운그레이드 시도 허용
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            data = jwt.decode(token, JWT_SECRET,
                              algorithms=["HS256", "HS384", "none"],
                              options={"verify_signature":
                                       False if "none" in token.lower() else True})
            return data
        except Exception:
            pass
    if "user_id" in session:
        u = db().execute("SELECT * FROM citizens WHERE id=?",
                          (session["user_id"],)).fetchone()
        if u:
            return {"sub": u["id"], "ssn": u["ssn"], "role": u["role"],
                    "level": u["authority_level"]}
    # V08 — Authority-Level 헤더 trust (권한 상승)
    al = request.headers.get("X-Authority-Level")
    if al and al.isdigit():
        return {"sub": -1, "ssn": "00000-00000", "role": "officer",
                "level": int(al)}
    return None


def log_audit(action: str, target: str = ""):
    """V12 — audit log 작성. but 본인이 self-tamper 가능."""
    actor = (current_user() or {}).get("ssn", "anonymous")
    db().execute("INSERT INTO audit_log (actor, action, target, timestamp, ip) "
                  "VALUES (?,?,?,?,?)",
                  (actor, action, target, datetime.utcnow().isoformat(),
                   request.remote_addr or ""))
    db().commit()


# ── Public ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/health")
def health():
    return {"status": "ok", "app": "GovPortal", "version": "1.0.0",
            "vulnerable": True}


# V01 — SAML 우회 (서명 검증 약함, alg=None 허용)
@app.route("/saml/login", methods=["GET", "POST"])
def saml_login():
    """SAML SSO 시뮬레이션 — XML token + HMAC.
    의도적 결함: (a) HMAC 검증 시 hmac.compare_digest 안 씀 (timing attack),
    (b) <Signature> 태그 없어도 통과, (c) IDP 화이트리스트 없음.
    """
    if request.method == "POST":
        saml_xml = request.form.get("SAMLResponse", "")
        try:
            decoded = base64.b64decode(saml_xml).decode()
        except Exception:
            decoded = saml_xml
        # V01 — XML signature 검증 안 함
        try:
            root = ET.fromstring(decoded)  # V14 XXE 가능
            assertion = root.find(".//{*}NameID")
            if assertion is None:
                # 필드명 만으로 우회 가능
                ssn_el = root.find(".//ssn")
                ssn = ssn_el.text if ssn_el is not None else ""
            else:
                ssn = assertion.text or ""
        except Exception as e:
            return f"SAML parse error: {e}", 400
        # V03 — issuer 무검증, signature 무검증
        c = db().execute("SELECT * FROM citizens WHERE ssn=?", (ssn,)).fetchone()
        if not c:
            # V02 — 자동 가입 (SAML JIT provisioning) — 임의 SSN 으로 계정 생성
            db().execute("INSERT INTO citizens (ssn, email, full_name, "
                          "password, role, authority_level) VALUES (?,?,?,?,?,?)",
                          (ssn, f"{ssn}@gov.auto", "SAML Auto", "x", "citizen", 1))
            db().commit()
            c = db().execute("SELECT * FROM citizens WHERE ssn=?",
                              (ssn,)).fetchone()
        session["user_id"] = c["id"]
        log_audit("saml_login", ssn)
        return redirect("/dashboard")
    return render_template("saml_login.html")


# V04 — login form SQLi
@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        ssn = request.form.get("ssn", "")
        pw = request.form.get("password", "")
        # V04 — SQLi
        q = f"SELECT * FROM citizens WHERE ssn = '{ssn}' AND password = '{pw}'"
        try:
            row = db().execute(q).fetchone()
        except Exception as e:
            return f"SQL: {e}", 500   # V23 verbose error
        if row:
            session["user_id"] = row["id"]
            log_audit("login", ssn)
            return redirect("/dashboard")
        err = "인증 실패"
    return render_template("login.html", err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── 시민 영역 ────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect("/login")
    apps = db().execute("SELECT * FROM applications WHERE citizen_id=? "
                         "ORDER BY id DESC", (u["sub"],)).fetchall()
    certs = db().execute("SELECT * FROM certificates WHERE citizen_id=?",
                          (u["sub"],)).fetchall()
    return render_template("dashboard.html", user=u, apps=apps, certs=certs)


# V09 — File Upload (확장자/MIME 검증 없음 + 임의 path 허용)
@app.route("/apply", methods=["GET", "POST"])
def apply():
    u = current_user()
    if not u:
        return redirect("/login")
    if request.method == "POST":
        atype = request.form.get("type", "")
        content = request.form.get("content", "")  # V11 stored XSS
        f = request.files.get("file")
        fn = ""
        if f:
            # V09 — 확장자 검증 없음, 사용자 제공 filename 그대로 사용
            fn = f.filename  # 의도적 — secure_filename 안 씀
            # V13 — Path traversal in filename
            f.save(str(UPLOAD_DIR / fn))
        # V10 — CSRF token 부재
        db().execute("INSERT INTO applications (citizen_id, application_type, "
                      "status, content, attached_file, submitted_at) "
                      "VALUES (?,?,?,?,?,?)",
                      (u["sub"], atype, "pending", content, fn,
                       datetime.utcnow().isoformat()))
        db().commit()
        log_audit("apply", atype)
        return redirect("/dashboard")
    return render_template("apply.html")


# V15 — IDOR — 다른 사람 신청서 조회
@app.route("/applications/<int:aid>")
def app_detail(aid: int):
    u = current_user()
    if not u:
        return redirect("/login")
    a = db().execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone()
    if not a:
        abort(404)
    # 의도적 — 소유 검증 없음
    citizen = db().execute("SELECT full_name, ssn FROM citizens WHERE id=?",
                            (a["citizen_id"],)).fetchone()
    return render_template("app_detail.html", app=a, citizen=citizen)


# V16 — IDOR — 다른 사람 신청서 강제 승인 (clerk 권한도 필요 X)
@app.route("/applications/<int:aid>/approve", methods=["POST"])
def app_approve(aid: int):
    u = current_user()
    if not u:
        return jsonify({"error": "auth"}), 401
    # 의도적 — clerk/officer 검증 없음
    db().execute("UPDATE applications SET status='approved', approved_by=? "
                  "WHERE id=?", (u["sub"], aid))
    db().commit()
    log_audit("approve", str(aid))
    # V07 — 예측 가능 cert_number 자동 발급
    a = db().execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone()
    if a:
        cert_num = f"CERT-{datetime.utcnow().year}-{a['citizen_id']:04d}-{aid:03d}"
        db().execute("INSERT INTO certificates (citizen_id, cert_type, "
                      "cert_number, issued_at, valid_until) VALUES (?,?,?,?,?)",
                      (a["citizen_id"], a["application_type"], cert_num,
                       datetime.utcnow().isoformat(), "2099-12-31"))
        db().commit()
    return jsonify({"approved": True, "cert_number": cert_num if a else None})


# V17 — Certificate download — path traversal + 직접 파일 읽기
@app.route("/cert/download")
def cert_download():
    fp = request.args.get("path", "")
    if not fp:
        return "path required", 400
    # 의도적 — 정규화 안 함, base 디렉토리 검증 없음
    try:
        with open(fp, "rb") as f:
            return f.read(), 200, {"Content-Type": "application/octet-stream"}
    except Exception as e:
        return f"err: {e}", 404


# V11 — Stored XSS (application content), V15 IDOR 와 결합
@app.route("/clerk/queue")
def clerk_queue():
    u = current_user()
    if not u:
        return redirect("/login")
    # V08 — clerk 검증 약함 (X-Authority-Level 트릭 통과)
    if u.get("level", 0) < 5:
        return "권한 부족 (level 5 이상 필요)", 403
    # 모든 신청서를 그대로 표시 (XSS 발현)
    apps = db().execute("SELECT * FROM applications WHERE status='pending' "
                         "ORDER BY submitted_at DESC").fetchall()
    return render_template("clerk_queue.html", apps=apps, user=u)


# V19 — admin API — auth 우회 (내부 IP 만 허용한다는 가정)
@app.route("/api/admin/citizens")
def admin_citizens():
    u = current_user()
    # V19 — Forwarded-For trust
    fwd = request.headers.get("X-Forwarded-For", "")
    if not u:
        if not (fwd.startswith("127.") or fwd.startswith("10.20.")):
            return jsonify({"error": "auth"}), 401
    rows = db().execute("SELECT * FROM citizens").fetchall()
    return jsonify([dict(r) for r in rows])


# V20 — Audit log tampering (본인 행적 삭제 가능)
@app.route("/api/audit/clear", methods=["POST"])
def audit_clear():
    u = current_user()
    if not u:
        return jsonify({"error": "auth"}), 401
    actor = request.args.get("actor", "")
    if not actor:
        return jsonify({"error": "actor required"}), 400
    # 의도적 — 본인 검증 없음, 모든 actor 의 로그 삭제 가능
    n = db().execute("DELETE FROM audit_log WHERE actor=?", (actor,)).rowcount
    db().commit()
    return jsonify({"deleted": n})


# V22 — Account merge (mass assignment + privilege escalation)
@app.route("/api/profile/update", methods=["POST"])
def profile_update():
    u = current_user()
    if not u:
        return jsonify({"error": "auth"}), 401
    data = request.get_json(force=True, silent=True) or {}
    # role / authority_level / ssn 까지 받음 (Mass assignment)
    fields, args = [], []
    for k in ("email", "full_name", "phone", "address", "role", "authority_level", "ssn"):
        if k in data:
            fields.append(f"{k}=?")
            args.append(data[k])
    if not fields:
        return jsonify({"error": "no fields"}), 400
    args.append(u["sub"])
    db().execute(f"UPDATE citizens SET {', '.join(fields)} WHERE id=?", args)
    db().commit()
    return jsonify({"updated": True})


# V14 — XXE (SAML XML import 별개로 공식 endpoint)
@app.route("/api/applications/import", methods=["POST"])
def applications_import():
    raw = request.get_data()
    try:
        root = ET.fromstring(raw)  # 의도적 XXE
        return jsonify({"root_tag": root.tag,
                         "children": [c.tag for c in root]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# V21 — Default PIN (admin 설정 1234) 로 admin 모드 진입
@app.route("/admin/console", methods=["GET", "POST"])
def admin_console():
    if request.method == "POST":
        pin = request.form.get("pin", "")
        if pin == DEFAULT_ADMIN_PIN:
            session["admin_pin_ok"] = True
            return redirect("/admin/console")
        return "wrong PIN", 401
    if not session.get("admin_pin_ok"):
        return render_template("admin_pin.html")
    return render_template("admin_console.html")


# V06 — Open Redirect (clipped to /go endpoint)
@app.route("/go")
def go():
    nxt = request.args.get("to", "/")
    return redirect(nxt)


# V18 — PII bulk export — 별도 보호 없이
@app.route("/api/citizens/export.csv")
def citizens_export_csv():
    u = current_user()
    if not u:
        return "auth", 401
    rows = db().execute("SELECT ssn, email, full_name, phone, address "
                         "FROM citizens").fetchall()
    csv = "ssn,email,full_name,phone,address\n"
    csv += "\n".join(",".join(str(r[k]) for k in r.keys()) for r in rows)
    return csv, 200, {"Content-Type": "text/csv"}


# V24 — banner already in after_request (Apache 2.4.49 CVE-2021-41773 표기)
# V25 — 보안 헤더 부재 (X-Frame-Options 없음 → clickjacking)


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    port = int(os.environ.get("PORT", "3002"))
    app.run(host="0.0.0.0", port=port, debug=False)
