# Cloud Functions Gen2 compatible Dockerfile for PDF Worker
# Includes libmagic system library for python-magic MIME validation

FROM python:3.11-slim

# Install system dependencies
# libmagic1: Required for python-magic MIME type detection
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Cloud Functions uses PORT environment variable
ENV PORT=8080

# Run with functions-framework
CMD exec functions-framework --target=pdf_worker --port=$PORT