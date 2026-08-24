"""
PhishGuard AI — Root Application Entrypoint
Provides standard discovery for Railpack, Nixpacks, Heroku, Docker, and local runners.
"""
import os
import sys

# Ensure both repository root and backend/app are in sys.path
root_dir = os.path.dirname(os.path.abspath(__file__))
backend_app_dir = os.path.join(root_dir, "backend", "app")
backend_dir = os.path.join(root_dir, "backend")

for path in [root_dir, backend_app_dir, backend_dir]:
    if path not in sys.path:
        sys.path.insert(0, path)

# Import the FastAPI application instance
from backend.app.main import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
