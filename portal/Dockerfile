# el34 portal — FastAPI + Jinja2 + HTMX 기반 관리 대시보드
FROM python:3.12-slim

# 시각: 전체 el34 컨테이너 KST(Asia/Seoul) 통일.
ENV TZ=Asia/Seoul
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

COPY portal/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY portal/main.py /app/main.py
COPY portal/templates/ /app/templates/

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
