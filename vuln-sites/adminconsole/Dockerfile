FROM python:3.11-slim
# 시각: 전체 el34 컨테이너 KST(Asia/Seoul) 통일.
ENV TZ=Asia/Seoul
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping dnsutils whois git curl ca-certificates tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3004
ENV PORT=3004
CMD ["python", "app.py"]
