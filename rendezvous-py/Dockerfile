FROM python:3.14-slim

# Copy uv binary from the official uv image (avoids a pip install round-trip).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# wget is used by the Docker integration-test health-check that runs inside
# this container via `docker exec`.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install runtime dependencies first (layer cached until pyproject.toml changes).
COPY pyproject.toml .
RUN uv sync --no-dev

COPY . .

ENV DJANGO_SETTINGS_MODULE=rendezvous.settings
EXPOSE 8080

# PORT env var controls the listening port; defaults to 8080.
CMD ["sh", "-c", "uv run python manage.py runserver 0.0.0.0:${PORT:-8080}"]
