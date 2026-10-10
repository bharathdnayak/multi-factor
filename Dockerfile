# ==============================================================================
# Multi-Factor Behavioral Drift Continuous Security - Dockerfile
# Containerized Web Dashboard, REST APIs & Verification Engine
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HEADLESS_TEST=1

# Install system dependencies for OpenCV and graphics libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source and baseline assets
COPY . .

# Ensure runtime directories exist
RUN mkdir -p data/forensics data/logs data/sandbox data/harvested data/sessions models

# Expose Web Dashboard Port
EXPOSE 8000

# Default command: Launch Cyber-Ops Web Dashboard
CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8000"]
