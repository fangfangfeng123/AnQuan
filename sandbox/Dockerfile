# Dockerfile for the security evaluation sandbox image.
#
# This image is used as the execution environment for:
# - Environment reconnaissance (recon agent)
# - Static code analysis (code_audit agent: semgrep, bandit)
# - Dynamic PoC verification (poc_verify agent: curl, flask)
# - Target service execution (flask apps)

FROM python:3.11-slim

# Use Chinese mirrors for apt and pip
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null; \
    true

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure pip to use Chinese mirror
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ \
    && pip config set global.trusted-host mirrors.aliyun.com

# Install Python packages for scanning + target services
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    semgrep \
    bandit \
    requests \
    httpx

# Create working directories
RUN mkdir -p /workspace/source /workspace/tmp

WORKDIR /workspace
