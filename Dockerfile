# PhishGuard AI - Dockerfile
# Multi-stage build for production

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production
FROM python:3.11-slim

WORKDIR /app

# Create non-root user for security
RUN groupadd -r phishguard && useradd -r -g phishguard phishguard

# Copy installed packages from builder
COPY --from=builder /root/.local /home/phishguard/.local

# Copy application files
COPY . .

# Create models directory
RUN mkdir -p ml_models && chown -R phishguard:phishguard /app

# Switch to non-root user
USER phishguard

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health')" || exit 1

# Run with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]