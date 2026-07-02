# CCC Bastion — AI 기반 자율보안 에이전트

CCC 교육 플랫폼의 보안 실습 도구이자 **독립 배포 가능한 자율보안 에이전트**.

## 구조 (3-Layer Agent)

```
┌─ Manager Agent (gpt-oss:120b 권장) ───┐   실시간 운영
│  • 학생/운영자 세션 관리                │   빠른 반응
│  • skill 계획·실행·자기수정              │   multi-turn
└──────────────┬─────────────────────────┘
               ↓
┌─ SubAgent (gemma3:4b 권장) ────────────┐   경량 병렬
│  • 개별 shell 실행 (A2A 프로토콜)       │   각 VM runtime
│  • 명령 추출/생성 fallback               │
│  • output semantic check                │
└────────────────────────────────────────┘
```

## 주요 기능

- **PLANNING → EXECUTING → VALIDATING** 3단계 상태 머신
- Playbook 매칭 + 멀티스텝 Skill + 동적 Playbook 생성
- self-correction 루프: skill 실패 시 LLM 진단 + 대안 시도 (최대 2회)
- QA 응답 → 실행 전환 (정규식 + SubAgent 추출 fallback)
- HITL ask_user: 모호한 요청에 사람 답변 요청
- Experience DB로 과거 사례 축적 + Playbook 승격

## 설치

```bash
# pip install (레포 분리 후)
pip install git+https://github.com/mrgrit/bastion.git

# 또는 로컬
cd packages/bastion
pip install -e ".[full]"
```

## 환경변수

필수:
- `LLM_BASE_URL` — Ollama 서버 (예: 랩 내부 `http://10.20.30.220:11434` 또는 외부 `http://<host>:11434`)
- `LLM_MANAGER_MODEL` — Manager 모델 (기본: `gpt-oss:120b`)
- `LLM_SUBAGENT_MODEL` — SubAgent 모델 (기본: `gemma3:4b`)

선택:
- `BASTION_PORT` — API 포트 (기본: 8003)
- `DATABASE_URL` — Experience DB (PostgreSQL)

## 실행

```bash
# API 서버
python -m apps.bastion.api
# 또는 설치된 스크립트
bastion-api

# TUI (대화형)
python -m apps.bastion.main
```

## API 엔드포인트

- `POST /chat` — 자연어 요청 실행 (NDJSON 스트림)
- `POST /onboard` — VM 온보딩 (SSH 기반)
- `GET /skills` — Skill 목록
- `GET /playbooks` — Playbook 목록
- `GET /evidence` — 실행 기록
- `GET /health` — 헬스체크

## 문서

- [ARCHITECTURE.md](ARCHITECTURE.md) — 상세 아키텍처
- [TEST_REPORT.md](TEST_REPORT.md) — 실증 테스트 결과 (41.6% pass @ 3,090 케이스)

## 레포 분리 계획

현재 `github.com/mrgrit/ccc/packages/bastion/` → `github.com/mrgrit/bastion/`

분리 후:
- 독립 배포 (실무 SOC·MSSP 환경)
- CCC는 pip package 또는 git submodule로 참조
- API 경계 고정 (OpenAPI 스펙 문서화)
