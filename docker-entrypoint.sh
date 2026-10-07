#!/bin/sh
# Started as root, as the paisans toolkit starts it, this fixes what a
# deployment that writes its files through sudo cannot: /data is a bind mount
# Docker created as root, and SEED_FILE is a root-owned 0600 file because it
# carries the SMTP password. It hands both to `node` and then drops to `node`
# for good. Started as anyone else it does nothing, so the image behaves as it
# always did everywhere else.
set -eu
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data
  chown -R node:node /data
  if [ -n "${SEED_FILE:-}" ] && [ -f "$SEED_FILE" ]; then
    install -o node -g node -m 0600 "$SEED_FILE" /tmp/uptime-seed.json
    SEED_FILE=/tmp/uptime-seed.json
    export SEED_FILE
  fi
  exec setpriv --reuid=node --regid=node --init-groups "$@"
fi
exec "$@"
