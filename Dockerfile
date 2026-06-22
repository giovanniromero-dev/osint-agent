# Build stage
FROM python:3.11-slim AS builder

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.lock .
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock

RUN playwright install chromium --with-deps

# Runtime stage
FROM python:3.11-slim

ENV OSINT_HEADLESS=true \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /ms-playwright /ms-playwright

RUN apt-get update && playwright install-deps chromium \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/reports /app/chrome_profile \
    && chown -R appuser:appuser /app /ms-playwright /home/appuser

USER appuser

VOLUME ["/app/reports"]

ENTRYPOINT ["python", "agent.py"]
CMD ["--help"]
