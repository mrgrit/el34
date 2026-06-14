# Bastion 레포 분리 마이그레이션 가이드

현재 상태: `github.com/mrgrit/ccc/packages/bastion/` (CCC 모노레포 내부)
목표: `github.com/mrgrit/bastion/` (독립 레포)

## 분리 방법

### 옵션 A: git subtree split (기록 보존)

```bash
cd /path/to/ccc
git subtree split --prefix=packages/bastion -b bastion-split

# 새 레포로 push
git remote add bastion git@github.com:mrgrit/bastion.git
git push bastion bastion-split:main
```

### 옵션 B: 깨끗한 초기화

```bash
# 새 디렉토리에 복사
mkdir -p ~/bastion-repo && cd ~/bastion-repo
cp -r /path/to/ccc/packages/bastion/* .
git init -b main
git add -A
git commit -m "initial: CCC Bastion 분리"
git remote add origin git@github.com:mrgrit/bastion.git
git push -u origin main
```

## 분리 후 CCC 쪽 작업

### 1. import 경로 변경

```python
# 이전
from packages.bastion import run_command
from packages.bastion.agent import BastionAgent

# 이후 (pip install 방식)
from bastion import run_command
from bastion.agent import BastionAgent
```

영향 파일:
- `apps/bastion/api.py`
- `apps/bastion/main.py`
- `apps/ccc_api/src/main.py` (L582, L625 등)

### 2. requirements 추가

`ccc/requirements.txt`:
```
ccc-bastion @ git+https://github.com/mrgrit/bastion.git@main
# 또는 특정 버전 고정
ccc-bastion==1.0.0
```

### 3. packages/bastion/ 삭제 (또는 symlink)

```bash
# 분리 완료 검증 후
rm -rf packages/bastion
# 또는 dev 환경에서 편집 편의 위해 submodule
git submodule add git@github.com:mrgrit/bastion.git packages/bastion
```

### 4. Docker 이미지 (독립 배포)

Bastion 레포에 `Dockerfile`:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e ".[full]"
EXPOSE 8003
CMD ["python", "-m", "apps.bastion.api"]
```

## API 경계 고정

CCC가 Bastion을 외부 서비스로 호출 시:
- HTTP API (`http://bastion:8003`)
- OpenAPI 스펙: `GET /openapi.json`
- 버전 태그 (semver)
- 하위 호환성: 브레이킹 변경 시 major bump

## 분리 체크리스트

- [ ] `packages/bastion/pyproject.toml` 완성 ✓
- [ ] `README.md` 작성 ✓
- [ ] 소스 import를 `bastion.*`로 통일 (분리 시점에)
- [ ] subtree split 실행
- [ ] mrgrit/bastion 레포 생성 및 push
- [ ] CCC에서 pip install 테스트
- [ ] OpenAPI 스펙 공개
- [ ] Docker 이미지 빌드
- [ ] 실무 환경 배포 테스트

## 현재 분리 준비 완료 항목

- `pyproject.toml` + 의존성 목록
- `README.md` + `ARCHITECTURE.md`
- 자체 API (`apps/bastion/api.py`) — 독립 실행 가능
- 환경변수 기반 설정 (하드코딩 없음)
- 실증 테스트 결과 보존 (`TEST_REPORT.md`)
