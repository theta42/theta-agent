#!/bin/sh
# Demo: a 3rd-party bash app reads the secret the theta-agent rendered to disk.
# The agent rendered /etc/theta/rendered/db.env from a template + OpenBao.
echo "=== bash app reads the rendered secret ==="
if [ -f /etc/theta/rendered/db.env ]; then
  . /etc/theta/rendered/db.env
  echo "DB_USER=$DB_USER"
  echo "DB_PASS=$DB_PASS"
else
  echo "rendered secret not found — run render_secrets first"
  exit 1
fi
