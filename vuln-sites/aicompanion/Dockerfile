FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3005
ENV PORT=3005
ENV LLM_BACKEND=mock
CMD ["python", "app.py"]
