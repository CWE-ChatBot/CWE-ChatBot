# Multi-stage build for enhanced security
FROM python:3.11-slim@sha256:8df0e8faf75b3c17ac33dc90d76787bbbcae142679e11da8c6f16afae5605ea7 AS builder

# Install build dependencies with cleanup
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim@sha256:8df0e8faf75b3c17ac33dc90d76787bbbcae142679e11da8c6f16afae5605ea7

# Security-hardened environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Security features
    CHAINLIT_HOST=0.0.0.0 \
    CHAINLIT_PORT=8080 \
    # Memory security
    MALLOC_CHECK_=2

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create secure non-root user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --create-home --no-log-init --shell /bin/false appuser

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy application files with secure permissions
COPY --chown=appuser:appuser main.py .
COPY --chown=appuser:appuser healthcheck.py .

# Create directories with proper permissions
RUN mkdir -p /app/logs && \
    chmod 755 /app && \
    chmod 750 /app/logs && \
    chmod 644 /app/*.py && \
    chmod +x /app/healthcheck.py && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Secure health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python /app/healthcheck.py

# Start command for Cloud Run
CMD ["python", "-m", "chainlit", "run", "main.py", "--host", "0.0.0.0", "--port", "8080"]