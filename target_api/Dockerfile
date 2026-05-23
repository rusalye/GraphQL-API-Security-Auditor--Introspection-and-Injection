FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 4000
# Environment variables can be passed via docker-compose
ENV MONGO_URL="mongodb://localhost:27017"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "4000"]
