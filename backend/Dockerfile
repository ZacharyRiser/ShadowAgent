# Shadow Agent backend — production image.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# jq-free healthcheck: use python stdlib to probe /health.
RUN groupadd --system shadowagent \
    && useradd --system --gid shadowagent --create-home shadowagent

WORKDIR /app

# Optional shared-state backend for multi-instance deployments: build with
# --build-arg INSTALL_REDIS=true and set SHADOW_AGENT_REDIS_URL at runtime.
ARG INSTALL_REDIS=false
COPY requirements.txt ./
RUN if [ "$INSTALL_REDIS" = "true" ]; then \
        pip install --no-cache-dir -r requirements.txt redis==8.1.0; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY alembic.ini ./
COPY alembic ./alembic
COPY main.py env_loader.py database.py models.py \
     security_controls.py security_engine.py ./
COPY app ./app

RUN mkdir -p /data && chown -R shadowagent:shadowagent /app /data
USER shadowagent

ENV SHADOW_AGENT_DATABASE_PATH=/data/shadow_agent.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# Apply pending migrations, then serve. Single worker by design: the in-memory
# login throttle, rate limiter, and JWT revocation set are process-local.
CMD ["sh", "-c", "python -m alembic upgrade head && python -m uvicorn main:app --host 0.0.0.0 --port 8000"]
