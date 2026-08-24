FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for networking and building
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    whois \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy application files
COPY . /app

# Create a non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Expose default port
EXPOSE 8000

# Start the application with dynamic port support (Railway / Render / Cloud Run / Local)
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
