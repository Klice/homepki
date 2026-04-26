FROM mcr.microsoft.com/devcontainers/go:2-1.26-bookworm

# The Microsoft Go image ships an apt source for Yarn whose signing key has
# rotated; `apt-get update` fails with NO_PUBKEY, which then breaks any
# devcontainer feature that runs apt. We don't need yarn here, so drop it.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        sqlite3 \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
