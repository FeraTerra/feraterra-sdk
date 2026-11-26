FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARENA_NETWORK=testnet

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY sdk/ ./sdk/

RUN pip install --no-cache-dir . && \
    useradd --create-home --uid 10001 mcpuser

USER mcpuser
ENTRYPOINT ["feraterra-mcp"]
