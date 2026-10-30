# Multi-stage Dockerfile for Microsoft Active Directory MCP Server (Remote LDAP/LDAPS Mode)
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap-2.5-0 \
    libsasl2-2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ ./src/
COPY pyproject.toml ./

ENV PYTHONPATH=/app/src \
    AD_BACKEND=ldap \
    AD_MCP_MODE=READ_ONLY \
    PYTHONUNBUFFERED=1

# Non-root user for security
RUN useradd -m -u 10001 admcp && \
    mkdir -p /app/logs /app/reports_output && \
    chown -R admcp:admcp /app

USER admcp

ENTRYPOINT ["python", "-m", "ad_mcp"]

