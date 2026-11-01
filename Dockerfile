# One container: FastAPI API + built React dashboard on the same origin (dashboard at /app, health at /health).
# Runs anywhere Docker does (the free Render service uses render.yaml instead, no Docker needed):
#   docker build -t vectra . && docker run -p 7860:7860 vectra
# DEMO_MODE: no outbound network; the SQLite DB is rebuilt from backend/data/cache/ on every start.

# 1. Build the dashboard.
FROM node:22-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# 2. Python runtime, as an unprivileged user (uid 1000) that owns the app dir
#    (the app writes backend/data/vectra.db and the campaigns cache at startup).
FROM python:3.11-slim
RUN useradd -m -u 1000 user
WORKDIR /home/user/app
COPY --chown=user backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY --chown=user . .
COPY --chown=user --from=web /src/frontend/dist frontend/dist
USER user
ENV DEMO_MODE=true PYTHONUTF8=1 PORT=7860 MALLOC_ARENA_MAX=2
EXPOSE 7860
# prestart.py loads the cache + seeds the demo in its own process first, so the API starts lean (see render.yaml).
CMD ["sh", "-c", "cd backend && python -X utf8 ../scripts/prestart.py && exec python -X utf8 -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
