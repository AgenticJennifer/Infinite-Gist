FROM ghcr.io/trufflesecurity/trufflehog:3.90.8 AS trufflehog

FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.lock .
RUN pip install --user --no-cache-dir --retries 5 --timeout 120 -r requirements.lock

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git && \
    rm -rf /var/lib/apt/lists/*
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
RUN useradd --create-home --shell /bin/bash appuser && \
    mkdir -p /app/data && chown -R appuser:appuser /app
WORKDIR /app
COPY --chown=appuser:appuser --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH
COPY --chown=appuser:appuser alembic ./alembic
COPY --chown=appuser:appuser alembic.ini .
COPY --chown=appuser:appuser src ./src
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn src.backend.main:app --host 0.0.0.0 --port 8000"]
