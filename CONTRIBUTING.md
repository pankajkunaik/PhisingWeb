# Contributing to PhishGuard AI

Thank you for your interest in contributing! This document outlines the process and standards for contributing to this project.

---

## 🏗️ Project Structure

```
phishingai/
├── backend/          # FastAPI Python backend
│   ├── app/
│   │   ├── core/     # Config, cache helpers
│   │   ├── routers/  # Route handlers (auth, scan, threats, ai_chat)
│   │   ├── schemas/  # Pydantic request/response models
│   │   ├── services/ # Business logic (scanner, auth, reporter)
│   │   ├── database.py
│   │   └── main.py   # App entrypoint
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/         # Next.js 16 TypeScript app
│   └── src/
│       ├── app/      # Next.js App Router pages
│       └── lib/
│           └── api.ts # Centralized API client
├── ml/               # Machine learning pipeline
│   ├── features.py   # Feature extraction
│   ├── train.py      # Model training
│   └── models/       # Saved model artefacts
├── extension/        # Chrome Extension (Manifest V3)
├── docs/             # Architecture & API documentation
└── docker-compose.yml
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Node.js 20+
- Redis (optional — caching degrades gracefully without it)
- Git

### Backend Setup

```bash
cd backend
cp .env.example .env          # Fill in your SECRET_KEY
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd app
uvicorn main:app --reload --port 8000
```

API docs available at: http://localhost:8000/api/docs

### Frontend Setup

```bash
cd frontend
cp .env.local.example .env.local
npm install
npm run dev
```

App available at: http://localhost:3000

### With Docker (recommended)

```bash
cp backend/.env.example backend/.env
# Edit backend/.env and set SECRET_KEY
docker compose up --build
```

---

## 🔀 Git Workflow

1. **Fork** the repository
2. **Create** a feature branch from `develop`:
   ```bash
   git checkout -b feature/your-feature-name develop
   ```
3. **Commit** with conventional commits:
   - `feat:` — new feature
   - `fix:` — bug fix
   - `docs:` — documentation only
   - `refactor:` — code cleanup (no behaviour change)
   - `test:` — adding/fixing tests
4. **Push** and open a **Pull Request** against `develop`
5. PRs to `main` are only opened from `develop` after review

---

## ✅ Code Standards

### Backend (Python)
- Follow **PEP 8** — enforced via `ruff`
- All new endpoints must have Pydantic **request and response schemas**
- All new services must handle exceptions gracefully and log errors
- New API keys / secrets must be loaded from `core/config.py` (env vars only)

### Frontend (TypeScript)
- Use the centralized **`src/lib/api.ts`** client — never raw `fetch()` with hardcoded URLs
- Type all API responses using the interfaces defined in `api.ts`
- Components must be in `src/components/` (not inline in pages)

### ML
- All feature changes in `ml/features.py` must update `FEATURE_KEYS` accordingly
- Retrain the model after feature changes: `python ml/train.py`
- Commit the new `ml/models/phishguard_model.json`

---

## 🧪 Running Tests

```bash
# Backend
cd backend
pytest app/tests/ -v

# Frontend
cd frontend
npx tsc --noEmit   # Type checking
npm run lint        # ESLint
```

---

## 🐛 Reporting Issues

Please open a GitHub Issue with:
- A clear title
- Steps to reproduce
- Expected vs. actual behaviour
- Your OS + Python/Node version

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
