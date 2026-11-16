#!/bin/sh
# strfry's writePolicy plugin: one long-running jq, one decision per line.
exec jq -c --unbuffered -f /app/write-policy.jq
