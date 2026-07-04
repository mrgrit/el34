FROM python:3.11-slim
# 시각: 전체 el34 컨테이너 KST(Asia/Seoul) 통일.
ENV TZ=Asia/Seoul
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3005
ENV PORT=3005
ENV LLM_BACKEND=mock
CMD ["python", "app.py"]
