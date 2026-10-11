# ==============================================================================
# Multi-Factor Behavioral Drift Continuous Security - Dockerfile
# Containerized Cyber-Ops Web Dashboard, REST APIs & Telemetry Streaming
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEADLESS_TEST=1 \
    HOST=0.0.0.0 \
    PORT=8000

# Install system dependencies for OpenCV and graphics libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user for security
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install Python dependencies first (leverages layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source and baseline assets
COPY . .

# Ensure runtime directories exist and assign permissions to appuser
RUN mkdir -p data/forensics data/logs data/sandbox data/harvested data/sessions data/benchmarks models && \
    chown -R appuser:appuser /app

USER appuser

# Expose Web Dashboard Port
EXPOSE 8000

# Container healthcheck against REST status endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Default command: Launch Cyber-Ops Web Dashboard
CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8000"]
