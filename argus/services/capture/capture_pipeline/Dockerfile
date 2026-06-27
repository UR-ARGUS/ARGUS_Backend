# Selenium 캡처 파이프라인 — Headless Chrome 포함 이미지
FROM python:3.12-slim

# Chrome 실행에 필요한 시스템 라이브러리 + Chrome 본체 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    fonts-liberation \
    fonts-nanum \
    libnss3 \
    libxss1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libgbm1 \
    && wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY capture_job.py selenium_capture.py main.py ./

# 캡처 결과물이 쌓일 디렉토리 (volume으로 마운트될 예정)
RUN mkdir -p /app/captures /app/zap_results

ENTRYPOINT ["python3", "main.py"]
