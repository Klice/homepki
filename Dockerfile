# syntax=docker/dockerfile:1.7
#
# Multi-stage build → static homepki binary on top of Alpine.
#
# Why Alpine and not scratch / distroless? The deploy runner shells out to
# `sh -c <post_command>` for operator-supplied reload commands, and we want
# `wget` available for the HEALTHCHECK probe. Alpine adds ~5 MB and makes
# both work without extra layers.

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

# --- build stage ------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

WORKDIR /src

# Cache module downloads in a separate layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO disabled → modernc.org/sqlite is pure Go and the result is a static
# binary that runs on any glibc/musl host. -trimpath strips local paths;
# -s -w drops the symbol table for a smaller image.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/homepki ./cmd/homepki

# --- runtime stage ----------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache ca-certificates wget tzdata sqlite su-exec && \
    addgroup -S -g 1000 homepki && \
    adduser  -S -D -u 1000 -G homepki -h /home/homepki homepki && \
    mkdir -p /data && chown homepki:homepki /data

COPY --from=build /out/homepki /usr/local/bin/homepki
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Entrypoint runs as root so it can chown /data and recreate the
# homepki user at the host-supplied PUID/PGID before dropping
# privileges via su-exec. Pass --user on the docker command to
# bypass that path entirely.
WORKDIR /data
VOLUME ["/data"]

EXPOSE 8080

ENV CM_LISTEN_ADDR=:8080 \
    CM_DATA_DIR=/data \
    CM_LOG_FORMAT=json \
    PUID=1000 \
    PGID=1000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
