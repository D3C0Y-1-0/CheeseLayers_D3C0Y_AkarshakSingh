# One container: FastAPI API + built React dashboard on the same origin (dashboard at /app, health at /health).
# Used by the Hugging Face Space (scripts/deploy_hf.py); also runs anywhere Docker does:
#   docker build -t vectra . && docker run -p 7860:7860 vectra
# DEMO_MODE: no outbound network; the SQLite DB is rebuilt from backend/data/cache/ on every start.

# 1. Build the dashboard.
FROM node:22-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# 2. Python runtime. Hugging Face runs Spaces as uid 1000, so the app dir must be owned by that user
#    (the app writes backend/data/vectra.db and the campaigns cache at startup).
FROM python:3.11-slim
RUN useradd -m -u 1000 user
WORKDIR /home/user/app
COPY --chown=user backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY --chown=user . .
COPY --chown=user --from=web /src/frontend/dist frontend/dist
USER user
ENV DEMO_MODE=true PYTHONUTF8=1 PORT=7860
EXPOSE 7860
CMD ["sh", "-c", "cd backend && exec python -X utf8 -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
