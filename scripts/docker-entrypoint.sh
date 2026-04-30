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

# Recreate the homepki user/group at the requested IDs. Cheap on every
# start and avoids needing the `shadow` package just for usermod.
deluser  homepki 2>/dev/null || true
delgroup homepki 2>/dev/null || true
addgroup -S -g "$PGID" homepki
adduser  -S -D -u "$PUID" -G homepki -h /home/homepki homepki

# Bind-mounted /data on Unraid is pre-created at PUID:PGID by the host;
# elsewhere it may be a fresh named volume owned by root. Either way,
# align ownership so the homepki user can write its SQLite DB.
chown -R homepki:homepki /data

exec su-exec homepki:homepki "$@"
