# 6v6 assessor — 읽기 전용 평가 수집 레이어 (FastAPI + docker SDK + httpx)
# portal 의 마운트·docker.sock 패턴을 참고하되 별도 경량 서비스로 분리.
FROM python:3.12-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY assessor/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 패키지 구조 보존 (relative import) — assessor.app:app 으로 기동
COPY assessor/ /app/assessor/

EXPOSE 8000
CMD ["uvicorn", "assessor.app:app", "--host", "0.0.0.0", "--port", "8000"]
