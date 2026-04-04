#!/bin/sh
set -e
cd /app/backend
gunicorn config.wsgi:application \
  --bind 127.0.0.1:8000 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout 300 \
  --access-logfile - \
  --error-logfile - &

exec nginx -g "daemon off;"
