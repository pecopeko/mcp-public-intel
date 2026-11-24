FROM python:3.11-slim

ARG MCP_SERVER_NAME="io.github.pecopeko/mcp-public-intel"

LABEL io.modelcontextprotocol.server.name="${MCP_SERVER_NAME}"
LABEL org.opencontainers.image.source="https://github.com/pecopeko/mcp-public-intel"
LABEL org.opencontainers.image.description="Live SEC EDGAR XBRL, ATS jobs, Shopify catalogs, Substack & Podcast transcripts MCP server"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["mcp-public-intel"]
