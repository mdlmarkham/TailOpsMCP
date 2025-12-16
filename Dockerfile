FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY README.md .
COPY setup.py .

# Create non-root user
RUN useradd -r -s /bin/false systemmanager

# Create directories
RUN mkdir -p /var/log/systemmanager /etc/systemmanager
RUN chown -R systemmanager:systemmanager /app /var/log/systemmanager

# Switch to non-root user
USER systemmanager

# Expose port for HTTP transport
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["python", "-m", "src.mcp_server"]
