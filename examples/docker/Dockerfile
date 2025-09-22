# Multi-stage Dockerfile for security log redaction
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --user -r /tmp/requirements.txt

FROM python:3.11-slim as runtime

# Create non-root user
RUN groupadd -r redactor && useradd -r -g redactor redactor

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /home/redactor/.local

# Set up application directory
WORKDIR /opt/redactor

# Copy application files
COPY redact.py .
COPY redaction-rules.yaml .
COPY test_performance.py .

# Copy example configurations
COPY examples/ ./examples/

# Create directories for logs and config
RUN mkdir -p /var/log/redacted /etc/redactor /tmp/redactor && \
    chown -R redactor:redactor /opt/redactor /var/log/redacted /etc/redactor /tmp/redactor

# Switch to non-root user
USER redactor

# Make sure PATH includes user site-packages
ENV PATH=/home/redactor/.local/bin:$PATH
ENV PYTHONPATH=/home/redactor/.local/lib/python3.11/site-packages

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 redact.py --validate-config --rules redaction-rules.yaml || exit 1

# Default command
ENTRYPOINT ["python3", "redact.py"]
CMD ["--help"]

# Labels
LABEL maintainer="Security Team"
LABEL version="1.0.0"
LABEL description="Security log redaction container"