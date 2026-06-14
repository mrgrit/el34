"""manager_ai — CCC Manager AI 시스템

Claude Code 아키텍처를 참고한 교육 플랫폼 매니저 AI.
시스템 프롬프트 동적 조합 + SubAgent 제어 + 학생 분석.

주요 기능:
1. 인프라 자동 세팅 (VM에 소프트웨어 설치)
2. 학생별 학습 분석 + 피드백
3. Lab 자동 검증 (SubAgent 연동)
4. CTF 문제 생성
5. 시스템 상태 모니터링
"""
from __future__ import annotations
import os
import json
from typing import Any

import httpx

OLLAMA_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434")
MODEL = os.getenv("LLM_MANAGER_MODEL", "gpt-oss:120b")

# ── 시스템 프롬프트 조합 (Claude Code src/ 참고) ──

SYSTEM_SECTIONS = {
    "identity": """너는 CCC(Cyber Combat Commander)의 Manager AI다.
사이버보안 교육 플랫폼의 중앙 관리 시스템으로서, 학생 인프라 설정, 학습 분석, 실습 검증, 시스템 운영을 담당한다.""",

    "capabilities": """사용 가능한 도구:
- run_command: SubAgent에 명령 실행 (SSH 불필요, A2A 프로토콜)
- check_health: SubAgent 헬스체크
- install_package: 패키지 설치 (apt, pip, docker)
- read_log: 로그 파일 읽기
- analyze_student: 학생 학습 데이터 분석
- generate_ctf: CTF 문제 생성
- verify_lab: 실습 결과 검증""",

    "infra_context": """학생 인프라 구성:
- attacker (Kali): nmap, metasploit, hydra, sqlmap, burpsuite, impacket
- secu: nftables, suricata, sysmon, osquery, auditd
- web: ModSecurity, JuiceShop, DVWA, WebGoat, sysmon, osquery
- siem: Wazuh, SIGMA, OpenCTI, 로그 수집
- windows: Sysmon, Ghidra, x64dbg, Autopsy
- manager: Ollama, bastion""",

    "rules": """규칙:
1. 명령 실행 시 반드시 SubAgent URL을 통해 실행한다 (직접 SSH 금지)
2. 위험한 명령(rm -rf, DROP TABLE 등)은 사전 확인 후 실행
3. 학생 데이터는 프라이버시 보호 (다른 학생에게 노출 금지)
4. 모든 작업은 CCCNet 블록체인에 기록
5. 한국어로 응답""",
}


def compose_prompt(student_info: dict | None = None, task_context: str = "") -> str:
    """시스템 프롬프트 동적 조합"""
    sections = [
        SYSTEM_SECTIONS["identity"],
        SYSTEM_SECTIONS["capabilities"],
        SYSTEM_SECTIONS["infra_context"],
    ]

    if student_info:
        sections.append(f"""현재 학생 정보:
- 이름: {student_info.get('name', '?')}
- 학번: {student_info.get('student_id', '?')}
- 랭크: {student_info.get('rank', 'rookie')}
- 블록: {student_info.get('total_blocks', 0)}
- 인프라: {json.dumps(student_info.get('infras', []), ensure_ascii=False)[:300]}""")

    if task_context:
        sections.append(f"작업 컨텍스트: {task_context}")

    sections.append(SYSTEM_SECTIONS["rules"])
    return "\n\n".join(sections)


def execute(instruction: str, student_info: dict | None = None, subagent_url: str = "") -> dict:
    """Manager AI 작업 실행 — LLM에 지시 → 실행 계획 → SubAgent 실행"""
    prompt = compose_prompt(student_info, instruction)

    plan_prompt = f"""{instruction}

실행 가능한 bash 명령어 목록을 JSON으로 생성하세요:
{{"tasks":[{{"order":1,"command":"명령어","description":"설명","target":"subagent_url"}}]}}"""

    try:
        r = httpx.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": plan_prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.3},
            },
            timeout=120.0,
        )
        content = r.json().get("message", {}).get("content", "")
        # JSON 추출
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            return {"plan": data.get("tasks", []), "raw": content}
    except Exception as e:
        return {"error": str(e), "plan": []}
    return {"plan": [], "raw": content if 'content' in dir() else ""}


def setup_vm(role: str, ip: str, ssh_user: str = "ccc") -> list[str]:
    """VM별 설치 명령어 목록 생성"""
    commands = {
        "secu": [
            "apt-get update -y",
            "apt-get install -y nftables suricata auditd",
            "systemctl enable --now nftables suricata auditd",
            # sysmon for linux
            "wget -qO /tmp/sysmon.deb https://packages.microsoft.com/repos/microsoft-prod/pool/main/s/sysmonforlinux/sysmonforlinux_*.deb && dpkg -i /tmp/sysmon.deb || true",
            # osquery
            "apt-get install -y osquery || true",
        ],
        "web": [
            "apt-get update -y",
            "apt-get install -y apache2 libapache2-mod-security2 auditd docker.io",
            "systemctl enable --now apache2 docker auditd",
            "docker pull bkimminich/juice-shop && docker run -d -p 3000:3000 bkimminich/juice-shop",
            "docker pull vulnerables/web-dvwa && docker run -d -p 8081:80 vulnerables/web-dvwa",
            "docker pull webgoat/webgoat && docker run -d -p 8082:8080 webgoat/webgoat",
        ],
        "siem": [
            "apt-get update -y",
            "curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && bash wazuh-install.sh -a || true",
            "apt-get install -y auditd",
            "pip3 install sigma-cli || true",
        ],
        "windows": [
            "echo 'Windows setup requires manual steps or Ansible'",
        ],
        "attacker": [
            "apt-get update -y",
            "apt-get install -y nmap hydra sqlmap nikto dirb gobuster seclists",
        ],
        "manager": [
            "curl -fsSL https://ollama.ai/install.sh | sh",
            f"ollama pull {MODEL}",
        ],
    }
    return commands.get(role, [])
