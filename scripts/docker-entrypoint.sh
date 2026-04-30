#!/bin/sh
#
# Adapt the runtime UID/GID to PUID/PGID and drop privileges before
# starting homepki. Follows the linuxserver.io convention so the image
# fits cleanly into Unraid (PUID=99 PGID=100), Synology DSM, and any
# other host where the bind-mounted /data has a fixed owner that
# doesn't match the image's default 1000:1000.
#
# When the container is started with --user (so we're already a
# non-root UID), the dance is skipped and the binary is exec'd
# directly.
set -eu

# When invoked without an explicit subcommand, run the homepki binary.
# Lets users override with `docker run ... homepki <flag>` or shell
# into the container with `docker run ... sh`.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    set -- /usr/local/bin/homepki "$@"
fi

if [ "$(id -u)" -ne 0 ]; then
    exec "$@"
fi

PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Ensure a group exists at PGID. Reuse one if it's already provisioned
# at that ID — Alpine's base image already has `users` at GID 100,
# which is exactly what Unraid asks for, and `addgroup -S -g 100` would
# otherwise fail with "gid '100' in use". Only mint a fresh group when
# nothing claims the GID yet, evicting any stale `homepki` group from
# a previous run or the build-time provisioning.
if ! getent group "$PGID" >/dev/null; then
    delgroup homepki 2>/dev/null || true
    addgroup -S -g "$PGID" homepki
fi
group_name=$(getent group "$PGID" | cut -d: -f1)

# Same shape for the user: reuse an existing UID, or mint one and
# evict the stale `homepki` entry first so the name is free.
if ! getent passwd "$PUID" >/dev/null; then
    deluser homepki 2>/dev/null || true
    adduser -S -D -u "$PUID" -G "$group_name" -h /home/homepki homepki
fi

# Bind-mounted /data on Unraid is pre-created at PUID:PGID by the host;
# elsewhere it may be a fresh named volume owned by root. Either way,
# align ownership so the runtime user can write its SQLite DB.
chown -R "$PUID:$PGID" /data

exec su-exec "$PUID:$PGID" "$@"
