#!/bin/sh
# Railway mounts the volume owned by root; strfry runs as its own user.
set -e
chown -R strfry:strfry /app/strfry-db
exec su-exec strfry /app/strfry --config=/etc/strfry.conf relay
