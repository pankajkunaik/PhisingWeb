FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system deps for whois/dns
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/app ./app
COPY ml ./ml

# Create a non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Start the app with dynamic port support (Render / Cloud Run / Local)
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
