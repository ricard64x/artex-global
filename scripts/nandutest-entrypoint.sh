#!/bin/sh
# Bootstrap persistent Fly volume ownership once, then drop privileges.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "[nandutest] initial volume setup requires root; refusing privileged application runtime" >&2
  exit 1
fi
if [ ! -d /app/data ]; then
  mkdir -p /app/data
fi
# Volume may be root-owned from the previous upstream image. Snapshot before
# switching images. Preserve existing content and perform only ownership changes.
chown -R 10001:10001 /app/data
exec gosu artex /app/start.sh "$@"
