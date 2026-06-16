# Deployment Guide: PhishGuard AI

This document provides deployment configurations for both local runtime and cloud environments.

## 1. Local Startup Execution

### Backend
1. Ensure Python 3.10+ is installed.
2. Install packages:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Initialize the database and start the server:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Frontend
1. Ensure Node.js 18+ is installed.
2. Navigate to `frontend/` and install dependencies:
   ```bash
   npm install
   ```
3. Run the hot-reloading development server:
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) to view the console dashboard.

---

## 2. Docker Architecture

We recommend deploying the API using the following Docker configuration.

### [NEW] `docker/Dockerfile.backend` (FastAPI)
Create a Dockerfile in the project root or `docker/` folder:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ml/ /app/ml/
COPY backend/app/ /app/backend/app/

EXPOSE 8000

ENV PORT=8000
ENV DATABASE_URL=sqlite:///./phishguard.db

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT"]
```

---

## 3. Cloud Provider Targets

### A. Frontend (Next.js) -> Vercel
*   Deploy using Vercel Next.js presets.
*   Configure the Environment variable:
    *   `NEXT_PUBLIC_API_URL` = `https://your-api-backend-url.railway.app`

### B. Backend (FastAPI) -> Render / Railway / Heroku
*   Set up deployment from GitHub linking the repository.
*   Select the Dockerfile: `docker/Dockerfile.backend`.
*   Configure Environment variables:
    *   `DATABASE_URL` = `postgresql://user:pass@host:port/dbname`
    *   `SECRET_KEY` = `your_strong_cryptographic_jwt_key`
