# Cloud Functions Gen2 compatible Dockerfile for PDF Worker
# Includes libmagic system library for python-magic MIME validation
# Security: SHA256-pinned base image, non-root user

FROM python:3.11-slim@sha256:ff8533f48e12b705fc20d339fde2ec61d0b234dd9366bab3bc84d7b70a45c8c0

# Install system dependencies
# libmagic1: Required for python-magic MIME type detection
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security (CWE-250 mitigation)
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser appuser && \
    mkdir -p /workspace && \
    chown -R appuser:appuser /workspace

# Set working directory
WORKDIR /workspace

# Copy requirements and install Python dependencies (as root for pip)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code with correct ownership
COPY --chown=appuser:appuser main.py .

# Switch to non-root user for runtime
USER appuser

# Cloud Functions uses PORT environment variable
ENV PORT=8080

# Run with functions-framework
CMD exec functions-framework --target=pdf_worker --port=$PORT --host=0.0.0.0