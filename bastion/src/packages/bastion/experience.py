"""Bastion Experience Learning — 오버피팅 방지 설계의 경험 학습 모듈

opsclaw experience_service 패턴 참고.
정확한 프롬프트 암기가 아닌 카테고리 수준 일반화로 경험을 축적한다.

오버피팅 방지 전략:
1. 카테고리 일반화: "패스워드 확인" + "패스워드 설정" → 같은 system_auth 카테고리
2. 최소 증거 임계값: 3회 이상 성공해야 경험으로 승격
3. 성공률 기반: 70%+ 성공률만 유효한 경험
4. 부정 경험: 실패 패턴도 경고로 활용
5. 용량 제한 + LRU: 100개 초과 시 미사용 경험 삭제
6. 시간 감쇠: 오래된 경험일수록 영향력 감소
"""
from __future__ import annotations
import json
import re
import sqlite3
from datetime import datetime, timedelta


# ── 카테고리 정의 (일반화의 핵심) ──────────────────────────────────

CATEGORY_RULES = [
    (re.compile(r'password|패스워드|계정|PAM|chage|login\.defs|passwd|shadow', re.I), "system_auth"),
    (re.compile(r'nmap|scan|port|스캔|포트', re.I), "network_scan"),
    (re.compile(r'curl\s|http|api|REST|웹.*요청', re.I), "web_request"),
    (re.compile(r'nikto|dirb|gobuster|웹.*취약', re.I), "web_vuln_scan"),
    (re.compile(r'hydra|brute|크래킹|john|hashcat', re.I), "credential_attack"),
    (re.compile(r'suricata|IDS|IPS|알림.*탐지', re.I), "ids_ops"),
    (re.compile(r'wazuh|siem|alerts\.log|에이전트.*목록', re.I), "siem_ops"),
    (re.compile(r'nftables|방화벽|firewall|iptables', re.I), "firewall_ops"),
    (re.compile(r'docker|container|컨테이너|compose', re.I), "container_ops"),
    (re.compile(r'audit|감사|auditd|auditctl', re.I), "audit_ops"),
    (re.compile(r'ssh|sshd|배너|banner', re.I), "ssh_ops"),
    (re.compile(r'log|로그|rsyslog|syslog|journalctl', re.I), "log_ops"),
    (re.compile(r'ollama|LLM|프롬프트|AI|모델', re.I), "ai_ops"),
    (re.compile(r'ssl|tls|인증서|openssl|certificate', re.I), "tls_ops"),
    (re.compile(r'modsecurity|WAF|차단.*로그', re.I), "waf_ops"),
    (re.compile(r'backup|백업|tar|복원', re.I), "backup_ops"),
    (re.compile(r'cron|스케줄|예약', re.I), "schedule_ops"),
    (re.compile(r'find.*suid|권한.*상승|privilege|setuid', re.I), "privesc"),
    (re.compile(r'report|보고서|종합|요약', re.I), "reporting"),
]


class ExperienceLearner:
    """Bastion 경험 학습 엔진 — 카테고리 수준 일반화"""

    MIN_EVIDENCE = 3          # 경험 승격 최소 증거 수
    SUCCESS_THRESHOLD = 0.7   # 경험 승격 최소 성공률
    MAX_EXPERIENCES = 100     # 용량 제한
    DECAY_DAYS = 30           # 시간 감쇠 기준일

    CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS experience (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at      TEXT DEFAULT (datetime('now')),
        updated_at      TEXT DEFAULT (datetime('now')),
        last_used       TEXT DEFAULT (datetime('now')),
        pattern_key     TEXT UNIQUE,
        category        TEXT,
        skill           TEXT,
        target_vm       TEXT,
        command_template TEXT,
        success_count   INTEGER DEFAULT 0,
        fail_count      INTEGER DEFAULT 0,
        total_count     INTEGER DEFAULT 0,
        keywords        TEXT DEFAULT '[]',
        examples        TEXT DEFAULT '[]',
        outcome         TEXT DEFAULT ''
    )"""

    def __init__(self, db: sqlite3.Connection | None = None, db_path: str = ""):
        self._db = db
        self._db_path = db_path
        self._ensure_table()

    def _connect(self):
        if self._db:
            return self._db, False
        return sqlite3.connect(self._db_path), True

    def _ensure_table(self):
        try:
            conn, should_close = self._connect()
            conn.execute(self.CREATE_SQL)
            conn.commit()
            if should_close:
                conn.close()
        except Exception:
            pass

    # ── 카테고리 분류 (일반화) ─────────────────────────────────────

    @staticmethod
    def classify(message: str) -> str:
        """메시지에서 카테고리 추출. 오버피팅 방지: 프롬프트가 아닌 카테고리로 일반화."""
        for pattern, category in CATEGORY_RULES:
            if pattern.search(message):
                return category
        return "general"

    @staticmethod
    def extract_keywords(message: str) -> list[str]:
        """메시지에서 핵심 키워드 추출 (2글자+ 한글, 3글자+ 영어, 기술 용어)."""
        words = set()
        for m in re.finditer(r'[가-힣]{2,}', message):
            words.add(m.group())
        for m in re.finditer(r'[a-zA-Z][\w.-]{2,}', message):
            words.add(m.group().lower())
        # 불용어 제거
        stopwords = {"에서", "으로", "해줘", "하시오", "사용하여", "명령으로", "실행", "확인", "설정"}
        return sorted(words - stopwords)

    def _make_pattern_key(self, category: str, target_vm: str, skill: str) -> str:
        return f"{category}:{target_vm}:{skill}"

    @staticmethod
    def _generalize_command(command: str) -> str:
        """명령어에서 IP/경로를 플레이스홀더로 치환하여 일반화."""
        tpl = re.sub(r'\d+\.\d+\.\d+\.\d+', '{IP}', command)
        tpl = re.sub(r'/tmp/\S+', '{TMPFILE}', tpl)
        return tpl[:200]

    # ── 기록 + 자동 승격 ──────────────────────────────────────────

    def record(self, message: str, skill: str, target_vm: str,
               command: str = "", success: bool = True):
        """실행 결과를 기록하고 자동 승격 판단."""
        category = self.classify(message)
        pattern_key = self._make_pattern_key(category, target_vm, skill)
        keywords = self.extract_keywords(message)
        cmd_tpl = self._generalize_command(command)

        try:
            conn, should_close = self._connect()
            conn.row_factory = sqlite3.Row

            existing = conn.execute(
                "SELECT * FROM experience WHERE pattern_key = ?", (pattern_key,)
            ).fetchone()

            now = datetime.now().isoformat()

            if existing:
                # 기존 패턴 업데이트
                new_success = existing["success_count"] + (1 if success else 0)
                new_fail = existing["fail_count"] + (0 if success else 1)
                new_total = existing["total_count"] + 1

                # 예시 목록 업데이트 (최대 3개, 중복 제거)
                examples = json.loads(existing["examples"] or "[]")
                if success and message[:60] not in [e[:60] for e in examples]:
                    examples.append(message[:80])
                    examples = examples[-3:]  # 최근 3개만

                # 키워드 병합
                old_kw = set(json.loads(existing["keywords"] or "[]"))
                merged_kw = sorted(old_kw | set(keywords))[:20]

                conn.execute("""
                    UPDATE experience SET
                        updated_at = ?, last_used = ?,
                        success_count = ?, fail_count = ?, total_count = ?,
                        examples = ?, keywords = ?,
                        command_template = CASE WHEN ? != '' AND ? = 1 THEN ? ELSE command_template END
                    WHERE pattern_key = ?
                """, (now, now, new_success, new_fail, new_total,
                      json.dumps(examples, ensure_ascii=False),
                      json.dumps(merged_kw, ensure_ascii=False),
                      cmd_tpl, int(success), cmd_tpl,
                      pattern_key))
            else:
                # 새 패턴 생성
                conn.execute("""
                    INSERT INTO experience
                    (pattern_key, category, skill, target_vm, command_template,
                     success_count, fail_count, total_count,
                     keywords, examples)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """, (pattern_key, category, skill, target_vm, cmd_tpl,
                      1 if success else 0,
                      0 if success else 1,
                      json.dumps(keywords, ensure_ascii=False),
                      json.dumps([message[:80]] if success else [], ensure_ascii=False)))

            conn.commit()
            self.enforce_capacity(conn)
            if should_close:
                conn.close()
        except Exception:
            pass

    # ── 경험 검색 (planning 시 사용) ──────────────────────────────

    def lookup(self, message: str, top_k: int = 5) -> list[dict]:
        """메시지에 관련된 경험을 검색. 카테고리 + 키워드 기반 (exact match 아님)."""
        category = self.classify(message)
        keywords = self.extract_keywords(message)

        try:
            conn, should_close = self._connect()
            conn.row_factory = sqlite3.Row

            # 1. 같은 카테고리의 경험 조회
            rows = conn.execute(
                "SELECT * FROM experience WHERE category = ? ORDER BY total_count DESC LIMIT ?",
                (category, top_k * 2)
            ).fetchall()

            # 카테고리 매칭이 부족하면 키워드로 보충
            if len(rows) < top_k and keywords:
                kw_clause = " OR ".join("keywords LIKE ?" for _ in keywords[:3])
                kw_params = [f"%{kw}%" for kw in keywords[:3]]
                extra = conn.execute(
                    f"SELECT * FROM experience WHERE ({kw_clause}) "
                    f"AND pattern_key NOT IN ({','.join('?' for _ in rows)}) "
                    f"ORDER BY total_count DESC LIMIT ?",
                    kw_params + [r["pattern_key"] for r in rows] + [top_k]
                ).fetchall()
                rows = list(rows) + list(extra)

            if should_close:
                conn.close()

            # 스코어링: 성공률 × 빈도 × 시간 감쇠
            scored = []
            for r in rows:
                r = dict(r)
                total = r["total_count"] or 1
                success_rate = r["success_count"] / total
                freq_score = min(total / 10, 1.0)  # 10회 이상이면 만점
                decay = self._decay_weight(r.get("last_used", ""))
                r["score"] = success_rate * freq_score * decay
                r["success_rate"] = success_rate
                scored.append(r)

            scored.sort(key=lambda x: x["score"], reverse=True)
            return scored[:top_k]

        except Exception:
            return []

    def _decay_weight(self, last_used: str) -> float:
        """시간 감쇠: 오래된 경험일수록 가중치 감소."""
        if not last_used:
            return 0.5
        try:
            last = datetime.fromisoformat(last_used)
            days = (datetime.now() - last).days
            return max(0.1, 1.0 - (days / self.DECAY_DAYS) * 0.5)
        except Exception:
            return 0.5

    # ── Planning 컨텍스트 생성 ────────────────────────────────────

    def get_context(self, message: str) -> str:
        """planning prompt에 주입할 경험 컨텍스트.
        승격 기준(MIN_EVIDENCE + SUCCESS_THRESHOLD)을 충족한 경험만 포함."""
        experiences = self.lookup(message, top_k=5)
        if not experiences:
            return ""

        lines = ["[학습된 경험]"]
        positive_count = 0
        negative_count = 0

        for exp in experiences:
            total = exp["total_count"] or 1
            success_rate = exp["success_rate"]
            is_promoted = (total >= self.MIN_EVIDENCE and success_rate >= self.SUCCESS_THRESHOLD)
            is_negative = (total >= self.MIN_EVIDENCE and success_rate < 0.3)

            if is_promoted:
                # 긍정 경험: 추천
                cmd_hint = exp.get("command_template", "")[:60]
                line = (f"- {exp['category']} → {exp['target_vm']}에서 {exp['skill']} "
                        f"(성공률 {success_rate:.0%}, {total}회)")
                if cmd_hint:
                    line += f"\n  예: {cmd_hint}"
                lines.append(line)
                positive_count += 1
            elif is_negative:
                # 부정 경험: 경고
                lines.append(
                    f"- ⚠ {exp['category']} → {exp['target_vm']}에서 {exp['skill']}: "
                    f"실패 {exp['fail_count']}회/{total}회 — 다른 접근 권장"
                )
                negative_count += 1

        if positive_count == 0 and negative_count == 0:
            return ""  # 승격된 경험이 없으면 컨텍스트 없음

        return "\n".join(lines)

    # ── 용량 관리 ─────────────────────────────────────────────────

    def enforce_capacity(self, conn=None):
        """MAX_EXPERIENCES 초과 시 LRU 삭제."""
        try:
            _conn, should_close = (conn, False) if conn else self._connect()
            count = _conn.execute("SELECT COUNT(*) FROM experience").fetchone()[0]
            if count > self.MAX_EXPERIENCES:
                _conn.execute("""
                    DELETE FROM experience WHERE id IN (
                        SELECT id FROM experience
                        ORDER BY last_used ASC, total_count ASC
                        LIMIT ?
                    )
                """, (count - self.MAX_EXPERIENCES,))
                _conn.commit()
            if should_close:
                _conn.close()
        except Exception:
            pass

    # ── Playbook 자동 승격 (3단계: 결정화) ────────────────────────

    PROMOTE_TO_PLAYBOOK_THRESHOLD = 5   # Playbook 승격 최소 증거 수
    PROMOTE_SUCCESS_RATE = 0.8          # Playbook 승격 최소 성공률

    def promote_to_playbook(self, playbooks_dir: str = "") -> list[str]:
        """성공률 높은 경험을 Playbook YAML로 자동 생성.

        승격 조건: total >= 5회, 성공률 >= 80%.
        이미 같은 pattern_key의 Playbook이 있으면 건너뜀.

        Returns: 생성된 Playbook ID 목록
        """
        import os, yaml
        if not playbooks_dir:
            # _resolve_playbooks_dir 재사용 — CCC/flat 양 레이아웃 자동 감지
            from packages.bastion.playbook import PLAYBOOKS_DIR as _PD
            playbooks_dir = _PD
        os.makedirs(playbooks_dir, exist_ok=True)

        # 이미 존재하는 playbook_id 수집
        existing_ids = set()
        for f in os.listdir(playbooks_dir):
            if f.endswith(".yaml"):
                try:
                    with open(os.path.join(playbooks_dir, f)) as fh:
                        pb = yaml.safe_load(fh)
                    if pb:
                        existing_ids.add(pb.get("playbook_id", ""))
                except Exception:
                    pass

        created = []
        try:
            conn, should_close = self._connect()
            conn.row_factory = sqlite3.Row

            rows = conn.execute("""
                SELECT * FROM experience
                WHERE total_count >= ?
                AND CAST(success_count AS REAL) / MAX(total_count, 1) >= ?
                ORDER BY success_count DESC
            """, (self.PROMOTE_TO_PLAYBOOK_THRESHOLD, self.PROMOTE_SUCCESS_RATE)).fetchall()

            for row in rows:
                row = dict(row)
                pb_id = f"exp-{row['pattern_key'].replace(':', '-')}"

                if pb_id in existing_ids:
                    continue

                # 명령어 템플릿이 없으면 건너뜀
                cmd_tpl = row.get("command_template", "")
                if not cmd_tpl or cmd_tpl == "{IP}":
                    continue

                skill = row.get("skill", "shell")
                target_vm = row.get("target_vm", "attacker")
                category = row.get("category", "general")
                success_rate = row["success_count"] / max(row["total_count"], 1)

                # 예시에서 대표 프롬프트 추출
                examples = json.loads(row.get("examples", "[]"))
                desc = examples[0] if examples else row["pattern_key"]

                playbook = {
                    "playbook_id": pb_id,
                    "title": f"{category} 자동 생성 ({success_rate:.0%} 성공률)",
                    "description": desc[:100],
                    "source": "experience_auto_promote",
                    "pattern_key": row["pattern_key"],
                    "success_rate": round(success_rate, 2),
                    "evidence_count": row["total_count"],
                    "steps": [{
                        "name": f"{category} 실행",
                        "skill": skill,
                        "params": {
                            "target": target_vm,
                            "command": cmd_tpl,
                        },
                    }],
                }

                pb_file = os.path.join(playbooks_dir, f"{pb_id}.yaml")
                with open(pb_file, "w", encoding="utf-8") as fh:
                    yaml.dump(playbook, fh, allow_unicode=True,
                              default_flow_style=False, sort_keys=False)

                # experience에 승격 기록
                conn.execute(
                    "UPDATE experience SET outcome = ? WHERE pattern_key = ?",
                    (f"promoted_to_playbook:{pb_id}", row["pattern_key"])
                )
                created.append(pb_id)
                existing_ids.add(pb_id)

            conn.commit()
            if should_close:
                conn.close()
        except Exception:
            pass

        return created

    # ── 통계 ──────────────────────────────────────────────────────

    def stats(self) -> dict:
        try:
            conn, should_close = self._connect()
            total = conn.execute("SELECT COUNT(*) FROM experience").fetchone()[0]
            promoted = conn.execute(
                "SELECT COUNT(*) FROM experience WHERE total_count >= ? AND "
                "CAST(success_count AS REAL) / MAX(total_count, 1) >= ?",
                (self.MIN_EVIDENCE, self.SUCCESS_THRESHOLD)
            ).fetchone()[0]
            categories = conn.execute(
                "SELECT category, COUNT(*) FROM experience GROUP BY category"
            ).fetchall()
            if should_close:
                conn.close()
            return {
                "total_patterns": total,
                "promoted": promoted,
                "categories": dict(categories),
            }
        except Exception:
            return {"total_patterns": 0, "promoted": 0, "categories": {}}
