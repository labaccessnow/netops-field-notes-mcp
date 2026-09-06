# Minimal image for clients that prefer to run the server in a container.
FROM python:3.12-slim

LABEL io.modelcontextprotocol.server.name="io.github.labaccessnow/netops-field-notes-mcp"
LABEL org.opencontainers.image.source="https://github.com/labaccessnow/netops-field-notes-mcp"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY netops_field_notes ./netops_field_notes
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# stdio transport: the client talks to the process over stdin/stdout.
ENTRYPOINT ["netops-field-notes-mcp"]
